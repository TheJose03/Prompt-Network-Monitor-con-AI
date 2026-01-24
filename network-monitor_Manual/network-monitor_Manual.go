package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/time/rate"
)

var (
	modshell32  = windows.NewLazySystemDLL("shell32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procIsUserAnAdmin = modshell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = modshell32.NewProc("ShellExecuteW")
	procOpenProcessToken = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modadvapi32.NewProc("GetTokenInformation")
)

// ============================
// Estructuras de Datos
// ============================

// Connection representa una conexión TCP
type Connection struct {
	LocalIP   string
	LocalPort string
	RemoteIP  string
	RemotePort string
	State     string
	PID       int
}

// ConnectionEvent representa un evento de conexión
type ConnectionEvent struct {
	Timestamp   time.Time
	ProcessID   int
	ProcessName string
	ExecPath    string
	RemoteIP    net.IP
	RemotePort  int
	State       string
	GeoInfo     GeoInfo
	IsProcessed bool
}

// GeoInfo contiene información geográfica de una IP
type GeoInfo struct {
	Country      string
	City         string
	Organization string
}

// BlacklistEntry representa una entrada en la lista negra
type BlacklistEntry struct {
	IP         string
	Process    string
	Organization string
	Reason     string
	Effects    string
}

// EdgeHashEntry representa un hash válido de Edge
type EdgeHashEntry struct {
	Date string `json:"fecha"`
	Hash string `json:"hash"`
	Path string `json:"ruta"`
}

// ============================
// Sistema de Almacenamiento
// ============================

// Storage maneja el almacenamiento persistente
type Storage struct {
	rootDir  string
	logsDir  string
	hashesDir string
	mu       sync.RWMutex
}

// NewStorage crea un nuevo sistema de almacenamiento
func NewStorage() *Storage {
	// Determinar directorio actual
	execDir, _ := os.Executable()
	rootDir := filepath.Dir(execDir)
	
	return &Storage{
		rootDir:  rootDir,
		logsDir:  filepath.Join(rootDir, "logs"),
		hashesDir: filepath.Join(rootDir, "hashes"),
	}
}

// Crear directorios necesarios
func (s *Storage) EnsureDirectories() error {
	dirs := []string{s.logsDir, s.hashesDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

// Archivos en raíz
func (s *Storage) WhitelistFile() string {
	return filepath.Join(s.rootDir, "whitelist.txt")
}

func (s *Storage) BlacklistFile() string {
	return filepath.Join(s.rootDir, "blacklist.txt")
}

func (s *Storage) LogFile() string {
	return filepath.Join(s.rootDir, "log_conexiones.txt")
}

// Archivos en subdirectorios
func (s *Storage) LogCSVFile() string {
	return filepath.Join(s.logsDir, "log_conexiones.csv")
}

func (s *Storage) LogJSONFile() string {
	return filepath.Join(s.logsDir, "log_conexiones.json")
}

func (s *Storage) UnknownFile() string {
	return filepath.Join(s.logsDir, "desconocidas.txt")
}

func (s *Storage) LoggedEventsFile() string {
	return filepath.Join(s.logsDir, "logged_events.txt")
}

func (s *Storage) EdgeHashFile() string {
	return filepath.Join(s.hashesDir, "edge_hashes.json")
}

// Nuevo: Archivo exclusivo para eventos de lista negra
func (s *Storage) BlacklistLogFile() string {
	return filepath.Join(s.logsDir, "blacklist_events.log")
}

// Cargar whitelist
func (s *Storage) LoadWhitelist() ([]string, error) {
	data, err := os.ReadFile(s.WhitelistFile())
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	var whitelist []string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if isValidIP(line) {
			whitelist = append(whitelist, line)
		}
	}
	return whitelist, nil
}

// Guardar en whitelist
func (s *Storage) SaveToWhitelist(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	f, err := os.OpenFile(s.WhitelistFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	_, err = f.WriteString(ip + "\n")
	return err
}

// Cargar blacklist
func (s *Storage) LoadBlacklist() ([]BlacklistEntry, error) {
	data, err := os.ReadFile(s.BlacklistFile())
	if err != nil {
		if os.IsNotExist(err) {
			return []BlacklistEntry{}, nil
		}
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	var blacklist []BlacklistEntry
	
	// Saltar cabecera
	skipHeader := true
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		if skipHeader {
			if strings.Contains(line, "IP") && strings.Contains(line, "Proceso") {
				continue
			}
			if strings.Contains(line, "----------------") {
				skipHeader = false
				continue
			}
			continue
		}
		
		// Si la línea no contiene "|", asumimos que es solo una IP
		if !strings.Contains(line, "|") {
			ip := strings.TrimSpace(line)
			if isValidIP(ip) {
				entry := BlacklistEntry{
					IP:         ip,
					Process:    "*",  // Bloquear cualquier proceso
					Organization: "Desconocido",
					Reason:     "Bloqueo automático",
					Effects:    "Impacto desconocido",
				}
				blacklist = append(blacklist, entry)
			}
			continue
		}
		
		// Dividir por '|'
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		
		ip := strings.TrimSpace(parts[0])
		if !isValidIP(ip) {
			continue
		}
		
		entry := BlacklistEntry{
			IP:         ip,
			Process:    strings.TrimSpace(parts[1]),
			Organization: "Desconocido",
			Reason:     "Bloqueo automático",
			Effects:    "Impacto desconocido",
		}
		
		if len(parts) > 2 {
			entry.Organization = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			entry.Reason = strings.TrimSpace(parts[3])
		}
		if len(parts) > 4 {
			entry.Effects = strings.TrimSpace(parts[4])
		}
		
		blacklist = append(blacklist, entry)
	}
	
	return blacklist, nil
}

// Cargar desconocidas
func (s *Storage) LoadUnknownList() ([]string, error) {
	data, err := os.ReadFile(s.UnknownFile())
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	var unknown []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if isValidIP(line) {
			unknown = append(unknown, line)
		}
	}
	return unknown, nil
}

// Cargar eventos registrados (SOLO PARA ESTA EJECUCIÓN)
func (s *Storage) LoadLoggedEvents() ([]string, error) {
	// En lugar de cargar del disco, devolvemos una lista vacía
	// Los eventos se registran solo para esta ejecución
	return []string{}, nil
}

// Guardar evento registrado
func (s *Storage) SaveLoggedEvent(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	f, err := os.OpenFile(s.LoggedEventsFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	_, err = f.WriteString(key + "\n")
	return err
}

// Verificar si evento ya registrado (SOLO EN ESTA EJECUCIÓN)
func (s *Storage) IsEventLogged(key string) (bool, error) {
	// En lugar de verificar en disco, mantenemos un mapa en memoria
	// para esta ejecución específica
	return false, nil
}

// Agregar a desconocidas (PERO NO BLOQUEAR)
func (s *Storage) AddToUnknownList(ip net.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Verificar si ya existe
	unknown, err := s.LoadUnknownList()
	if err != nil {
		return err
	}
	
	for _, uip := range unknown {
		if uip == ip.String() {
			return nil
		}
	}
	
	f, err := os.OpenFile(s.UnknownFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	_, err = f.WriteString(ip.String() + "\n")
	return err
}

// Escribir cabecera inicial
func (s *Storage) WriteInitialHeader() error {
	header := []string{
		"",
		"==================== INICIO DEL MONITOREO ====================",
		time.Now().Format("2006-01-02 15:04:05") + " -",
		"Actua como un EDR o un NDR profesional.",
		"Analiza estas conexiones salientes, evalua IPs, rutas del ejecutable y anomalias de ruta e IP.",
		"",
		"Actualiza o dame un listado de estas IPs:",
		" Lista negra:",
		"  Formato: Salida (formato TXT listo para pegar): MODO CONSOLA para solo copiar tipo pgsql o diff.",
		"IP                  | Proceso          | Organizacion     | Motivo                 | Efectos si se bloquea",
		"----------------|------------------|------------------|------------------------|-----------------------------------",
		"Ejemplo:",
		"1.1.1.1  | Nombre del Proceso no incluyas el .exe | Organizacion     | Motivo del bloqueo     | Efectos si se bloquea",
		" Lista blanca:",
		" Formato: IP (una por linea)",
		"",
		"Efectos negativos si se bloquea una IP en lista negra que tiene anomalia ya sea de ruta o ips:",
		" - Fallo en actualizaciones del sistema",
		" - Problemas de activacion",
		" - Fallos en apps que dependen de servicios en la nube",
		"",
		"Revisa anomalias en rutas",
		"===============================================================",
		"",
	}
	
	f, err := os.OpenFile(s.LogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	for _, line := range header {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	
	return nil
}

// Guardar log en texto - MANTENEMOS ESTE MÉTODO PERO NO SE USA PARA CONEXIONES DESCONOCIDAS
func (s *Storage) AppendLogText(timestamp time.Time, processName, ip, execPath, geo, estado string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	timestampStr := timestamp.Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("%s [%s] IP:%s Ruta:\"%s\" Ubi: %s => %s\n", 
		timestampStr, processName, ip, execPath, geo, estado)
	
	f, err := os.OpenFile(s.LogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	_, err = f.WriteString(logEntry)
	return err
}

// Guardar log en CSV
func (s *Storage) AppendLogCSV(timestamp time.Time, processName, ip, execPath, geo, estado string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	timestampStr := timestamp.Format("2006-01-02 15:04:05")
	
	csvEntry := fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
		timestampStr, processName, ip, execPath, geo, estado)
	
	// Verificar si archivo existe (para cabecera)
	_, err := os.Stat(s.LogCSVFile())
	fileExists := !os.IsNotExist(err)
	
	f, err := os.OpenFile(s.LogCSVFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	// Agregar cabecera si es nuevo
	if !fileExists {
		header := "Fecha,Proceso,IP,Ruta,Ubicacion,Estado\n"
		if _, err := f.WriteString(header); err != nil {
			return err
		}
	}
	
	_, err = f.WriteString(csvEntry)
	return err
}

// Guardar log en JSON
func (s *Storage) AppendLogJSON(timestamp time.Time, processName, ip, execPath, geo, estado string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Cargar historial existente
	var history []map[string]interface{}
	if data, err := os.ReadFile(s.LogJSONFile()); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &history); err != nil {
			history = []map[string]interface{}{}
		}
	}
	
	// Crear nuevo registro
	timestampStr := timestamp.Format("2006-01-02 15:04:05")
	newEntry := map[string]interface{}{
		"tiempo":     timestampStr,
		"proceso":    processName,
		"ip":         ip,
		"ruta":       execPath,
		"geo":        geo,
		"estado":     estado,
	}
	
	// Agregar al historial
	history = append(history, newEntry)
	
	// Guardar
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(s.LogJSONFile(), data, 0644)
}

// NUEVO: Guardar log exclusivo para eventos de lista negra
func (s *Storage) AppendBlacklistLog(timestamp time.Time, processName, ip, execPath, geo, reason, effects string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Verificar si es la primera vez (y añadir cabecera)
	_, err := os.Stat(s.BlacklistLogFile())
	isFirstTime := os.IsNotExist(err)
	
	if isFirstTime {
		header := []string{
			"==================== EVENTOS DE LISTA NEGRA ====================",
			"Todos los eventos aquí fueron bloqueados automáticamente por coincidir con la lista negra.",
			"Formato: [Fecha] [Proceso] IP:xxx Ruta:\"...\" Ubi: ... | MOTIVO: ... | EFECTOS: ...",
			"================================================================",
			"",
		}
		
		f, err := os.Create(s.BlacklistLogFile())
		if err != nil {
			return err
		}
		defer f.Close()
		
		for _, line := range header {
			if _, err := f.WriteString(line + "\n"); err != nil {
				return err
			}
		}
	}
	
	timestampStr := timestamp.Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("%s [%s] IP:%s Ruta:\"%s\" Ubi: %s | MOTIVO: %s | EFECTOS: %s\n",
		timestampStr, processName, ip, execPath, geo, reason, effects)
	
	f, err := os.OpenFile(s.BlacklistLogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	_, err = f.WriteString(logEntry)
	return err
}

// NUEVO: Guardar log de conexiones desconocidas con formato específico
func (s *Storage) AppendUnknownConnectionLog(timestamp time.Time, processName, ip, execPath, geo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	timestampStr := timestamp.Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("CONEXIÓN DESCONOCIDA: %s [%s] IP:%s Ruta:\"%s\" Ubi: %s\n",
		timestampStr, processName, ip, execPath, geo)
	
	f, err := os.OpenFile(s.LogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	
	_, err = f.WriteString(logEntry)
	return err
}

// ============================
// Sistema de Geolocalización
// ============================

// GeoLocator maneja las consultas de geolocalización
type GeoLocator struct {
	ctx        context.Context
	cancel     context.CancelFunc
	limiter    *rate.Limiter
	queue      chan net.IP
	results    chan GeoResult
	cache      sync.Map
	storage    *Storage
	mu         sync.Mutex
	pending    map[string]chan GeoResult
}

type GeoResult struct {
	IP    net.IP
	Info  GeoInfo
	Error error
}

// NewGeoLocator crea un nuevo localizador geográfico
func NewGeoLocator(storage *Storage) *GeoLocator {
	ctx, cancel := context.WithCancel(context.Background())
	
	// 45 solicitudes por minuto = 1 cada 1.33 segundos
	limiter := rate.NewLimiter(rate.Every(800*time.Millisecond), 1)
	
	locator := &GeoLocator{
		ctx:     ctx,
		cancel:  cancel,
		limiter: limiter,
		queue:   make(chan net.IP, 100),
		results: make(chan GeoResult, 100),
		storage: storage,
		pending: make(map[string]chan GeoResult),
	}
	
	// Iniciar workers
	go locator.worker()
	
	return locator
}

// Cerrar el localizador
func (g *GeoLocator) Close() {
	g.cancel()
}

// Enqueue agrega una IP a la cola de geolocalización
func (g *GeoLocator) Enqueue(ip net.IP) {
	select {
	case g.queue <- ip:
	default:
		// Cola llena, pero seguimos
	}
}

// GetResult obtiene el resultado de geolocalización
func (g *GeoLocator) GetResult(ip net.IP) GeoResult {
	ipStr := ip.String()
	
	g.mu.Lock()
	if ch, exists := g.pending[ipStr]; exists {
		g.mu.Unlock()
		return <-ch
	}
	
	// Crear canal para este IP
	ch := make(chan GeoResult, 1)
	g.pending[ipStr] = ch
	g.mu.Unlock()
	
	// Enviar a procesamiento
	g.Enqueue(ip)
	
	return <-ch
}

// worker procesa la cola de geolocalización
func (g *GeoLocator) worker() {
	for {
		select {
		case <-g.ctx.Done():
			return
		case ip := <-g.queue:
			// Verificar caché primero
			if cached, ok := g.getFromCache(ip); ok {
				g.sendResult(ip, GeoResult{IP: ip, Info: cached})
				continue
			}
			
			// Respetar límite de API
			if err := g.limiter.Wait(g.ctx); err != nil {
				g.sendResult(ip, GeoResult{IP: ip, Error: err})
				continue
			}
			
			// Realizar consulta
			info, err := g.fetchGeoInfo(ip)
			if err != nil {
				g.sendResult(ip, GeoResult{IP: ip, Error: err})
				continue
			}
			
			// Guardar en caché
			g.cache.Store(ip.String(), info)
			g.sendResult(ip, GeoResult{IP: ip, Info: info})
		}
	}
}

// sendResult envía el resultado al canal correspondiente
func (g *GeoLocator) sendResult(ip net.IP, result GeoResult) {
	ipStr := ip.String()
	
	g.mu.Lock()
	if ch, exists := g.pending[ipStr]; exists {
		delete(g.pending, ipStr)
		g.mu.Unlock()
		
		// Enviar resultado
		ch <- result
		close(ch)
	} else {
		g.mu.Unlock()
	}
}

// Obtener de caché
func (g *GeoLocator) getFromCache(ip net.IP) (GeoInfo, bool) {
	if val, ok := g.cache.Load(ip.String()); ok {
		return val.(GeoInfo), true
	}
	return GeoInfo{}, false
}

// Consultar API
func (g *GeoLocator) fetchGeoInfo(ip net.IP) (GeoInfo, error) {
	// Usar API de ip-api.com
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip.String())
	
	// Crear cliente con timeout
	client := &http.Client{Timeout: 5 * time.Second}
	
	resp, err := client.Get(url)
	if err != nil {
		return GeoInfo{}, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return GeoInfo{}, fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	
	// Parsear respuesta
	var result struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		City        string `json:"city"`
		Org         string `json:"org"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return GeoInfo{}, err
	}
	
	if result.Status != "success" {
		return GeoInfo{}, fmt.Errorf("API returned error status")
	}
	
	return GeoInfo{
		Country:      result.Country,
		City:         result.City,
		Organization: result.Org,
	}, nil
}

// ============================
// Sistema de Bloqueo
// ============================

// Firewall maneja el bloqueo de conexiones
type Firewall struct {
	storage *Storage
	mu      sync.Mutex
}

// NewFirewall crea un nuevo sistema de firewall
func NewFirewall(storage *Storage) *Firewall {
	return &Firewall{
		storage: storage,
	}
}

// MODIFICADO: Agregado parámetro blockType para indicar el tipo de bloqueo
// Block bloquea una IP
func (f *Firewall) Block(ip net.IP, processName, reason, blockType string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	
	// MODIFICADO: Incluir el tipo de bloqueo en el nombre de la regla
	displayName := fmt.Sprintf("NETWORK-MONITOR: %s [%s] - %s", ip, processName, blockType)
	
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", 
		"name="+displayName,
		"description="+reason,
		"dir=out",
		"remoteip="+ip.String(),
		"action=block")
	
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error creating firewall rule: %v", err)
	}
	
	// MODIFICADO: Mensaje de log más claro que indica el tipo de bloqueo
	if blockType == "Lista Negra" {
		log.Printf("🔴 BLOQUEO POR LISTA NEGRA: %s [%s] - %s", ip, processName, reason)
	} else if blockType == "Desconocida" {
		log.Printf("🟠 BLOQUEO POR DESCONOCIDA: %s [%s] - %s", ip, processName, reason)
	} else {
		log.Printf("BLOQUEO: %s [%s] - %s", ip, processName, reason)
	}
	return nil
}

// ============================
// Monitor de Conexiones
// ============================

// ConnectionMonitor monitorea conexiones activas
type ConnectionMonitor struct {
	ctx            context.Context
	cancel         context.CancelFunc
	storage        *Storage
	geoLocator     *GeoLocator
	firewall       *Firewall
	whitelist      []string
	blacklist      []BlacklistEntry
	unknownList    []string
	edgeHashes     []EdgeHashEntry
	edgePaths      []string
	selfPID        int
	executablePath string
	activeEvents   map[string]*ConnectionEvent
	activeEventsMu sync.Mutex
	criticalEvents chan ConnectionEvent
	geoQueue       chan net.IP
	wg             sync.WaitGroup
	loggedEvents   map[string]bool // Para evitar duplicados en esta ejecución
}

// NewConnectionMonitor crea un nuevo monitor
func NewConnectionMonitor() (*ConnectionMonitor, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	storage := NewStorage()
	if err := storage.EnsureDirectories(); err != nil {
		return nil, err
	}
	
	// Cargar listas
	whitelist, _ := storage.LoadWhitelist()
	blacklist, _ := storage.LoadBlacklist()
	unknownList, _ := storage.LoadUnknownList()
	
	// Cargar hashes de Edge
	edgeHashes, _ := storage.LoadEdgeHashes()
	
	// Obtener el PID del propio proceso
	selfPID := os.Getpid()
	
	// Obtener la ruta del ejecutable
	executablePath, err := os.Executable()
	if err != nil {
		executablePath = ""
	}
	
	// Escribir cabecera inicial (SOLO PARA ESTA EJECUCIÓN)
	storage.WriteInitialHeader()
	
	// Configurar monitor
	monitor := &ConnectionMonitor{
		ctx:            ctx,
		cancel:         cancel,
		storage:        storage,
		geoLocator:     NewGeoLocator(storage),
		firewall:       NewFirewall(storage),
		whitelist:      whitelist,
		blacklist:      blacklist,
		unknownList:    unknownList,
		edgeHashes:     edgeHashes,
		edgePaths: []string{
			"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
			"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
		},
		selfPID:        selfPID,
		executablePath: executablePath,
		activeEvents:   make(map[string]*ConnectionEvent),
		criticalEvents: make(chan ConnectionEvent, 1000),
		geoQueue:       make(chan net.IP, 100),
		loggedEvents:   make(map[string]bool), // Inicializar mapa vacío para esta ejecución
	}
	
	// Registrar hash de Edge si es nuevo
	monitor.RegisterEdgeHashIfNew()
	
	// Iniciar workers
	monitor.StartWorkers()
	
	return monitor, nil
}

// Cerrar el monitor
func (m *ConnectionMonitor) Close() {
	m.cancel()
	m.geoLocator.Close()
	m.wg.Wait()
}

// Iniciar workers
func (m *ConnectionMonitor) StartWorkers() {
	// Worker para bloqueo crítico
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case event := <-m.criticalEvents:
				m.ProcessCriticalEvent(event)
			case <-m.ctx.Done():
				return
			}
		}
	}()
}

// Procesar evento crítico (SOLO BLOQUEA LISTA NEGRA)
func (m *ConnectionMonitor) ProcessCriticalEvent(event ConnectionEvent) {
	// Verificar si ya fue procesada EN ESTA EJECUCIÓN
	key := fmt.Sprintf("%s-%s", event.RemoteIP, event.ProcessName)
	if _, exists := m.loggedEvents[key]; exists {
		return
	}
	
	// ✅ PRIMERO OBTENER LA GEOINFO (NO ESPERAR EN SEGUNDO PLANO)
	result := m.geoLocator.GetResult(event.RemoteIP)
	geoStr := "Ubicacion no disponible"
	
	if result.Error == nil {
		geoStr = fmt.Sprintf("%s, %s, Org: %s", 
			result.Info.Country, result.Info.City, result.Info.Organization)
	} else {
		// Si hay error, usar información parcial
		geoStr = fmt.Sprintf("Error: %v", result.Error)
	}
	
	// Verificar en lista negra
	var blacklistEntry *BlacklistEntry
	for i := range m.blacklist {
		// Si el campo Process es "*" (cualquier proceso) o coincide con el nombre del proceso
		if m.blacklist[i].IP == event.RemoteIP.String() &&
		   (m.blacklist[i].Process == "*" || strings.EqualFold(m.blacklist[i].Process, event.ProcessName)) {
			blacklistEntry = &m.blacklist[i]
			break
		}
	}
	
	// ⚠️ SOLO BLOQUEAR SI ESTÁ EN LISTA NEGRA
	if blacklistEntry != nil {
		// MODIFICADO: Agregado "Lista Negra" como tipo de bloqueo
		if err := m.firewall.Block(event.RemoteIP, event.ProcessName, blacklistEntry.Reason, "Lista Negra"); err == nil {
			// ✅ REGISTRAR SOLO EN EL ARCHIVO DE LISTA NEGRA
			m.storage.AppendBlacklistLog(
				event.Timestamp,
				event.ProcessName,
				event.RemoteIP.String(),
				event.ExecPath,
				geoStr,
				blacklistEntry.Reason,
				blacklistEntry.Effects,
			)

			// Registrar también en CSV y JSON para el dashboard
			estado := "Bloqueada (Lista Negra)"
			_ = m.storage.AppendLogCSV(
				event.Timestamp,
				event.ProcessName,
				event.RemoteIP.String(),
				event.ExecPath,
				geoStr,
				estado,
			)
			_ = m.storage.AppendLogJSON(
				event.Timestamp,
				event.ProcessName,
				event.RemoteIP.String(),
				event.ExecPath,
				geoStr,
				estado,
			)
			
			// Registrar como procesada EN ESTA EJECUCIÓN
			m.loggedEvents[key] = true
			
			// ✅ MENSAJE EN CONSOLA ESPECÍFICO PARA LISTA NEGRA
			log.Printf("🛡️ BLOQUEO (LISTA NEGRA): %s [%s] IP:%s Ruta:\"%s\" Ubi: %s | MOTIVO: %s | EFECTOS: %s", 
				event.Timestamp.Format("2006-01-02 15:04:05"),
				event.ProcessName,
				event.RemoteIP,
				event.ExecPath,
				geoStr,
				blacklistEntry.Reason,
				blacklistEntry.Effects)
		}
		return
	}
	
	// ⚠️ REGISTRAR CONEXIONES DESCONOCIDAS EN log_conexiones.txt CON FORMATO ESPECÍFICO
	m.storage.AppendUnknownConnectionLog(
		event.Timestamp,
		event.ProcessName,
		event.RemoteIP.String(),
		event.ExecPath,
		geoStr,
	)

	// Registrar también en CSV y JSON para el dashboard
	estadoDesconocida := "Desconocida"
	_ = m.storage.AppendLogCSV(
			event.Timestamp,
			event.ProcessName,
			event.RemoteIP.String(),
			event.ExecPath,
			geoStr,
			estadoDesconocida,
	)
	_ = m.storage.AppendLogJSON(
			event.Timestamp,
			event.ProcessName,
			event.RemoteIP.String(),
			event.ExecPath,
			geoStr,
			estadoDesconocida,
	)
	
	// Agregar a desconocidas
	m.storage.AddToUnknownList(event.RemoteIP)
	
	// Registrar como procesada EN ESTA EJECUCIÓN
	m.loggedEvents[key] = true
	
	// ✅ MENSAJE EN CONSOLA PARA CONEXIONES DESCONOCIDAS (PERO NO SE BLOQUEAN)
	log.Printf("🔍 CONEXIÓN DESCONOCIDA: %s [%s] IP:%s Ruta:\"%s\" Ubi: %s", 
		event.Timestamp.Format("2006-01-02 15:04:05"),
		event.ProcessName,
		event.RemoteIP,
		event.ExecPath,
		geoStr)
	
	// MODIFICADO: NO BLOQUEAR CONEXIONES DESCONOCIDAS
	// if err := m.firewall.Block(event.RemoteIP, event.ProcessName, "IP desconocida", "Desconocida"); err == nil {
	//    log.Printf("🟠 BLOQUEO POR DESCONOCIDA: %s [%s] - IP desconocida", 
	//        event.RemoteIP, event.ProcessName)
	// }
}

// Iniciar monitoreo
func (m *ConnectionMonitor) StartMonitoring() {
	ticker := time.NewTicker(100 * time.Millisecond) // 100ms de detección
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Obtener conexiones activas usando netstat
			conns, err := GetTCPConnections()
			if err != nil {
				log.Printf("Error obteniendo conexiones: %v", err)
				continue
			}
			
			// Agrupar por proceso
			processConnections := make(map[int][]string)
			for _, conn := range conns {
				if conn.State == "ESTABLISHED" {
					// Registrar todas las conexiones, incluyendo las locales
					processConnections[conn.PID] = append(processConnections[conn.PID], conn.RemoteIP)
				}
			}

			// Procesar cada proceso
			for pid, ips := range processConnections {
				// Omitir el propio proceso
				if pid == m.selfPID {
					continue
				}
			
				// Obtener información del proceso
				processName := GetProcessName(pid)
				execPath := GetProcessPath(pid)

				// Ignorar completamente Microsoft Edge (msedge) en cualquier equipo
				// para que no se registre como CONEXIÓN DESCONOCIDA ni aparezca
				// OleMainThreadWndName en la ruta.
				if strings.EqualFold(processName, "msedge") {
					continue
				}
				
				// Omitir si es el propio ejecutable
				if execPath == m.executablePath {
					continue
				}
				
				// === CORRECCIÓN CLAVE: DETECCIÓN MEJORADA DE EDGE ===
				isEdge := false
				edgeHash := ""
				
				// 1. Verificar por nombre del proceso primero (más confiable)
				if strings.EqualFold(processName, "msedge") {
					isEdge = true
					
					// 2. Si la ruta está vacía, intentar obtenerla de nuevo con método alternativo
					if execPath == "" {
						// Método alternativo usando tasklist
						cmd := exec.Command("tasklist", "/fi", fmt.Sprintf("pid eq %d", pid), "/fo", "list")
						output, err := cmd.Output()
						if err == nil {
							lines := strings.Split(string(output), "\n")
							for _, line := range lines {
								if strings.Contains(line, "Image Name:") {
									// Extraer ruta del proceso desde tasklist
									parts := strings.Split(line, ":")
									if len(parts) > 1 {
										processName := strings.TrimSpace(parts[1])
										// Construir ruta probable
										if processName == "msedge.exe" {
											// Rutas comunes de Edge
											commonPaths := []string{
												"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
												"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
											}
											for _, path := range commonPaths {
												if _, err := os.Stat(path); err == nil {
													execPath = path
													break
												}
											}
										}
									}
								}
							}
						}
					}
					
					// 3. Obtener hash si tenemos ruta
					if execPath != "" {
						edgeHash = GetProcessHash(execPath)
					}
				}
				
				// 4. Verificar si es Edge con hash válido
				if isEdge && edgeHash != "" && m.IsEdgeHashValid(edgeHash) {
					continue // ¡SKIP CORRECTO!
				}
				// === FIN CORRECCIÓN ===
				
				// Procesar cada IP
				for _, ipStr := range ips {
					ip := net.ParseIP(ipStr)
					if ip == nil {
						continue
					}
					
					// Buscar el puerto correspondiente para esta IP y proceso
					var connectionPort string
					for _, conn := range conns {
						if conn.PID == pid && conn.RemoteIP == ipStr && conn.State == "ESTABLISHED" {
							connectionPort = conn.RemotePort
							break
						}
					}
					
					// Verificar si es una IP local (incluyendo 127.0.0.1)
					isLocal := isLocalIP(ip)
					if isLocal {
						// NO mostrar log para 127.0.0.1 y ::1 (loopback)
						if ip.String() == "127.0.0.1" || ip.String() == "::1" {
							continue
						}
						// Log de conexión local detectada (con puerto)
						if connectionPort != "" {
							log.Printf("🔵 CONEXIÓN LOCAL: %s [%s:%s] -> %s", processName, ip, connectionPort, execPath)
						} else {
							log.Printf("🔵 CONEXIÓN LOCAL: %s [%s] -> %s", processName, ip, execPath)
						}

						// Guardar conexión local en archivo
						localLog := fmt.Sprintf("[%s] CONEXIÓN LOCAL: %s [%s:%s] -> %s\n",
							time.Now().Format("2006-01-02 15:04:05"), processName, ip, connectionPort, execPath)
						saveToLocalConnectionsFile(localLog)
						continue
					}
					
					// Verificación adicional: excluir explícitamente loopback si no fue capturada por isLocalIP
					if ip.String() == "127.0.0.1" || ip.String() == "::1" {
						continue
					}
					
					// Verificar si es una IP de API
					if isAPIEndpoint(ip) {
						continue
					}
					
					// Verificar whitelist
					isWhitelisted := false
					for _, wip := range m.whitelist {
						if wip == ip.String() {
							isWhitelisted = true
							break
						}
					}
					if isWhitelisted {
						continue
					}
					
					// Verificar si ya está en el estado activo
					key := fmt.Sprintf("%s-%s", ip, processName)
					m.activeEventsMu.Lock()
					_, exists := m.activeEvents[key]
					if !exists {
						// Crear evento
						event := ConnectionEvent{
							Timestamp:   time.Now(),
							ProcessID:   pid,
							ProcessName: processName,
							ExecPath:    execPath,
							RemoteIP:    ip,
							State:       "Desconocida",
							IsProcessed: false,
						}
						
						// Agregar a eventos activos
						m.activeEvents[key] = &event
						m.activeEventsMu.Unlock()
						
						// Enviar a procesamiento crítico
						select {
						case m.criticalEvents <- event:
						default:
							// Cola llena, pero seguimos
						}
					} else {
						m.activeEventsMu.Unlock()
					}
				}
			}
			
		case <-m.ctx.Done():
			return
		}
	}
}

// ============================
// Funciones de Sistema
// ============================

// IsUserAnAdmin verifica si el usuario actual es administrador
func IsUserAnAdmin() bool {
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}

// RequestElevation solicita elevación de privilegios (UAC)
func RequestElevation() {
	executable, _ := os.Executable()
	params := fmt.Sprintf(`"runas" "%s"`, executable)
	
	verb := windows.StringToUTF16Ptr("runas")
	file := windows.StringToUTF16Ptr(executable)
	parameters := windows.StringToUTF16Ptr(params)
	
	ret, _, err := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(parameters)),
		0,
		1, // SW_SHOWNORMAL
	)
	
	if ret < 32 {
		log.Fatalf("Error al solicitar elevación de privilegios: %v", err)
	}
	
	os.Exit(0)
}

// GetTCPConnections obtiene todas las conexiones TCP activas usando netstat
func GetTCPConnections() ([]Connection, error) {
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	// Parsear la salida de netstat
	lines := strings.Split(string(output), "\n")
	var connections []Connection
	
	// Expresión regular para parsear líneas de netstat
	// Ejemplo: TCP    192.168.1.100:5000     172.217.16.206:443    ESTABLISHED     1234
	re := regexp.MustCompile(`\s*(TCP|TCP6)\s+([\d\.:]+)\s+([\d\.:]+)\s+(\w+)\s+(\d+)`)
	
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 6 {
			protocol := matches[1]
			localAddr := matches[2]
			remoteAddr := matches[3]
			state := matches[4]
			pidStr := matches[5]
			
			// Convertir PID a entero
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				continue
			}
			
			// Parsear direcciones
			localIP, localPort, _ := net.SplitHostPort(localAddr)
			remoteIP, remotePort, _ := net.SplitHostPort(remoteAddr)
			
			// En Windows, los IPv6 tienen formato diferente
			if protocol == "TCP6" {
				// Eliminar los corchetes de IPv6
				remoteIP = strings.Trim(remoteIP, "[]")
			}
			
			connections = append(connections, Connection{
				LocalIP:   localIP,
				LocalPort: localPort,
				RemoteIP:  remoteIP,
				RemotePort: remotePort,
				State:     state,
				PID:       pid,
			})
		}
	}
	
	return connections, nil
}

// GetProcessPath obtiene la ruta del ejecutable por PID
func GetProcessPath(pid int) string {
	// Primero intentar con WMIC
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "ExecutablePath", "/value")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ExecutablePath=") {
				path := strings.TrimPrefix(line, "ExecutablePath=")
				path = strings.TrimSpace(path)
				if path != "" && path != "N/A" {
					return path
				}
			}
		}
	}

	// Segundo intento: usar PowerShell para obtener la ruta del proceso
	// Esto es más estable entre distintas versiones/idiomas de Windows
	psCommand := fmt.Sprintf("(Get-Process -Id %d -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path)", pid)
	cmd = exec.Command("powershell", "-Command", psCommand)
	output, err = cmd.Output()
	if err == nil {
		path := strings.TrimSpace(string(output))
		if path != "" && path != "N/A" {
			return path
		}
	}

	// Si no pudimos obtener una ruta válida por ningún método, devolvemos
	// cadena vacía para evitar valores como OleMainThreadWndName en la Ruta.
	return ""
}

// GetProcessName obtiene el nombre del proceso por PID
func GetProcessName(pid int) string {
	cmd := exec.Command("tasklist", "/fi", fmt.Sprintf("pid eq %d", pid), "/fo", "csv", "/nh")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	
	// Parsear la salida
	r := csv.NewReader(strings.NewReader(string(output)))
	records, err := r.ReadAll()
	if err != nil || len(records) == 0 {
		return "unknown"
	}
	
	// El nombre del proceso está en la primera columna
	processName := strings.Trim(records[0][0], `"`)
	
	// Eliminar .exe si existe
	if strings.HasSuffix(processName, ".exe") {
		processName = processName[:len(processName)-4]
	}
	
	return processName
}

// GetProcessHash obtiene el hash SHA256 del ejecutable
func GetProcessHash(path string) string {
	if path == "" {
		return ""
	}
	
	// Usar CertUtil para obtener el hash
	cmd := exec.Command("certutil", "-hashfile", path, "SHA256")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	
	// Parsear la salida
	lines := strings.Split(string(output), "\n")
	if len(lines) > 1 {
		// El hash está en la segunda línea
		hash := strings.TrimSpace(lines[1])
		return strings.ToUpper(hash)
	}
	
	return ""
}

// RegisterEdgeHashIfNew registra el hash de Edge si es nuevo
func (m *ConnectionMonitor) RegisterEdgeHashIfNew() {
	// Rutas comunes de Edge
	edgePaths := []string{
		"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
		"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
	}
	
	for _, path := range edgePaths {
		if _, err := os.Stat(path); err == nil {
			hash := GetProcessHash(path)
			if hash != "" {
				exists := false
				for _, entry := range m.edgeHashes {
					if strings.EqualFold(entry.Hash, hash) {
						exists = true
						break
					}
				}
				
				if !exists {
					newEntry := EdgeHashEntry{
						Date: time.Now().Format("2006-01-02 15:04:05"),
						Hash: hash,
						Path: path,
					}
					m.edgeHashes = append(m.edgeHashes, newEntry)
					m.storage.SaveEdgeHashes(m.edgeHashes)
					log.Printf("✅ Hash de Edge registrado: %s (Ruta: %s)", hash, path)
				}
			}
		}
	}
}

// IsEdgeHashValid verifica si el hash es válido para Edge
func (m *ConnectionMonitor) IsEdgeHashValid(hash string) bool {
	if hash == "" {
		return false
	}
	
	// Normalizar: eliminar espacios y convertir a mayúsculas
	normalizedHash := strings.ToUpper(strings.ReplaceAll(hash, " ", ""))
	
	for _, entry := range m.edgeHashes {
		normalizedEntry := strings.ToUpper(strings.ReplaceAll(entry.Hash, " ", ""))
		if normalizedEntry == normalizedHash {
			return true
		}
	}
	return false
}

// getDefaultGateway obtiene la dirección IP de la puerta de enlace predeterminada
func getDefaultGateway() (string, error) {
	cmd := exec.Command("cmd", "/c", "route print 0.0.0.0 | findstr \"0.0.0.0\"")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	
	// El formato de salida es: 0.0.0.0   0.0.0.0   192.168.1.1   192.168.1.100
	lines := strings.Fields(string(output))
	if len(lines) >= 3 {
		return strings.TrimSpace(lines[2]), nil
	}
	
	return "", fmt.Errorf("no se pudo determinar la puerta de enlace")
}

// isLocalIP verifica si una IP es local o privada
// Devuelve true para IPs privadas, false para direcciones especiales
func isLocalIP(ip net.IP) bool {
    if ip == nil {
        return false
    }

    // Lista de IPs que NO queremos considerar como locales
    excludeIPs := map[string]bool{
        "0.0.0.0":    true,  // dirección no enrutable
    }
    
    // Obtener la puerta de enlace predeterminada
    gatewayIP, _ := getDefaultGateway()
    if gatewayIP != "" {
        excludeIPs[gatewayIP] = true
    }
    
    ipStr := ip.String()
    
    // Verificar si la IP está en la lista de exclusión
    if excludeIPs[ipStr] {
        return false
    }
    
    // Verificar si es una dirección de loopback (127.0.0.0/8)
    if ip.IsLoopback() {
        return false
    }
    
    // Verificar rangos privados (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    if ip.IsPrivate() {
        return true
    }
    
    // Verificar si es una dirección de enlace local (169.254.0.0/16)
    if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
        return true
    }
    
    // Verificar si es una dirección IPv6 local
    if ip.To4() == nil && ip.IsGlobalUnicast() {
        return false
    }
    
    return false
}

// isAPIEndpoint verifica si una IP es un endpoint de API necesario
func isAPIEndpoint(ip net.IP) bool {
    if ip == nil {
        return false
    }
    
    // IPs conocidas de ip-api.com
	apiIPs := []string{
		"104.20.10.48",   // ip-api.com
		"104.20.11.48",   // ip-api.com
		"104.20.12.48",   // ip-api.com
		"104.20.13.48",   // ip-api.com
		"104.20.14.48",   // ip-api.com
		"104.20.15.48",   // ip-api.com
		"104.20.16.48",   // ip-api.com
		"104.20.17.48",   // ip-api.com
		"104.20.18.48",   // ip-api.com
		"104.20.19.48",   // ip-api.com
		"104.20.20.48",   // ip-api.com
		"104.20.21.48",   // ip-api.com
		"104.20.22.48",   // ip-api.com
		"104.20.23.48",   // ip-api.com
		"104.20.24.48",   // ip-api.com
		"104.20.25.48",   // ip-api.com
		"104.20.26.48",   // ip-api.com
		"104.20.27.48",   // ip-api.com
		"104.20.28.48",   // ip-api.com
		"104.20.29.48",   // ip-api.com
		"104.20.30.48",   // ip-api.com
		"104.20.31.48",   // ip-api.com
	}
	
	for _, apiIP := range apiIPs {
		if ip.String() == apiIP {
			return true
		}
	}
	
	return false
}

// isValidIP verifica si una cadena es una IP válida
func isValidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil
}

// saveToLocalConnectionsFile guarda las conexiones locales en un archivo TXT
func saveToLocalConnectionsFile(logEntry string) {
	// Crear directorio logs si no existe
	logsDir := "logs"
	if _, err := os.Stat(logsDir); os.IsNotExist(err) {
		os.Mkdir(logsDir, 0755)
	}

	// Archivo para conexiones locales
	filename := fmt.Sprintf("%s/local_connections.txt", logsDir)

	// Abrir archivo en modo append
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Usar fmt en lugar de log para evitar dependencias circulares
		fmt.Printf("Error al abrir archivo de conexiones locales: %v\n", err)
		return
	}
	defer file.Close()

	// Escribir entrada
	if _, err := file.WriteString(logEntry); err != nil {
		fmt.Printf("Error al escribir en archivo de conexiones locales: %v\n", err)
	}
}

// ============================
// Funciones de Almacenamiento Específico para Edge
// ============================

// LoadEdgeHashes carga los hashes de Edge desde disco
func (s *Storage) LoadEdgeHashes() ([]EdgeHashEntry, error) {
	data, err := os.ReadFile(s.EdgeHashFile())
	if err != nil {
		if os.IsNotExist(err) {
			return []EdgeHashEntry{}, nil
		}
		return nil, err
	}
	
	var hashes []EdgeHashEntry
	if err := json.Unmarshal(data, &hashes); err != nil {
		// Intentar como array único si falla
		var singleHash EdgeHashEntry
		if err := json.Unmarshal(data, &singleHash); err == nil {
			return []EdgeHashEntry{singleHash}, nil
		}
		return []EdgeHashEntry{}, nil
	}
	
	return hashes, nil
}

// SaveEdgeHashes guarda los hashes de Edge en disco
func (s *Storage) SaveEdgeHashes(hashes []EdgeHashEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	data, err := json.MarshalIndent(hashes, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(s.EdgeHashFile(), data, 0644)
}

// ============================
// Función Principal
// ============================

func main() {
	// Verificar privilegios de administrador
	if !IsUserAnAdmin() {
		log.Println("⚠️  Este programa requiere privilegios de administrador para funcionar correctamente")
		log.Println("🔒  Solicitando elevación de privilegios (UAC)...")
		
		// Solicitar elevación de privilegios
		RequestElevation()
		
		// Si llegamos aquí, significa que la elevación falló
		log.Fatal("No se pudo obtener privilegios de administrador. Por favor, ejecuta el programa como administrador.")
		return
	}
	
	log.Println("🚀 INICIANDO MONITOR DE CONEXIONES ULTRARRÁPIDO")
	log.Println("⏱️  Tiempo de detección: 100ms | Tiempo de BLOQUEO: <20ms")
	log.Println("🔍 ¡SOLO BLOQUEA IPs en LISTA NEGRA! (Nuevo: Registros exclusivos en logs/blacklist_events.log)")
	
	// Crear monitor
	monitor, err := NewConnectionMonitor()
	if err != nil {
		log.Fatalf("Error inicializando monitor: %v", err)
	}
	defer monitor.Close()
	
	// Crear archivos si no existen
	storage := monitor.storage
	
	// Crear directorio logs si no existe
	logsDir := "logs"
	if _, err := os.Stat(logsDir); os.IsNotExist(err) {
		os.Mkdir(logsDir, 0755)
	}
	
	// Crear archivo de conexiones locales con cabecera
	localConnectionsFile := fmt.Sprintf("%s/local_connections.txt", logsDir)
	if _, err := os.Stat(localConnectionsFile); os.IsNotExist(err) {
		header := "FECHA Y HORA              | CONEXIÓN LOCAL DETECTADA\n"
		header += "---------------------------|-------------------------------------------\n"
		os.WriteFile(localConnectionsFile, []byte(header), 0644)
	}
	
	if _, err := os.Stat(storage.WhitelistFile()); os.IsNotExist(err) {
		os.WriteFile(storage.WhitelistFile(), []byte(""), 0644)
	}
	
	if _, err := os.Stat(storage.BlacklistFile()); os.IsNotExist(err) {
		// Escribir cabecera de blacklist
		header := "IP                  | Proceso          | Organizacion     | Motivo                 | Efectos si se bloquea\n"
		header += "----------------|------------------|------------------|------------------------|-----------------------------------\n"
		os.WriteFile(storage.BlacklistFile(), []byte(header), 0644)
	}
	
	if _, err := os.Stat(storage.UnknownFile()); os.IsNotExist(err) {
		os.WriteFile(storage.UnknownFile(), []byte(""), 0644)
	}
	
	if _, err := os.Stat(storage.EdgeHashFile()); os.IsNotExist(err) {
		os.WriteFile(storage.EdgeHashFile(), []byte("[]"), 0644)
	}
	
	// Iniciar dashboard web en localhost:8080 en paralelo
	go StartDashboardServer(storage)

	// Abrir automáticamente el dashboard en el navegador por defecto
	go func() {
		time.Sleep(1500 * time.Millisecond)
		cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", "http://localhost:8080/")
		_ = cmd.Start()
	}()
	
	log.Println("\nMonitoreando TODAS las conexiones salientes...")
	log.Println("Presiona Ctrl+C para detener.\n")
	
	// Iniciar monitoreo
	monitor.StartMonitoring()
}