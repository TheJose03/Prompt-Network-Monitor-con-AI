package main

import (
    "encoding/json"
    "html/template"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"
)

type DashboardData struct {
    Connections []LogEntry
    UnknownIPs  []string
    Blacklist   []BlacklistEntry
    Whitelist   []string
    RawLog      string
    Sessions    []string
}

type LogEntry struct {
    Tiempo    string `json:"tiempo"`
    Proceso   string `json:"proceso"`
    IP        string `json:"ip"`
    Ruta      string `json:"ruta"`
    Geo       string `json:"geo"`
    Estado    string `json:"estado"`
}

// StartDashboardServer inicia el servidor HTTP en localhost:8080
func StartDashboardServer(storage *Storage) {
    tmplPath := filepath.Join(storage.rootDir, "dashboard.html")
    tpl, err := template.ParseFiles(tmplPath)
    if err != nil {
        log.Printf("Error cargando plantilla HTML: %v", err)
        return
    }

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        data := DashboardData{}

        // Cargar conexiones desde JSON si existe
        if b, err := os.ReadFile(storage.LogJSONFile()); err == nil && len(b) > 0 {
            var entries []LogEntry
            if err := json.Unmarshal(b, &entries); err == nil {
                // Ordenar de más nuevas a más antiguas: último registro del log primero
                for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
                    entries[i], entries[j] = entries[j], entries[i]
                }
                data.Connections = entries
            }
        }

        // Cargar desconocidas
        if unknown, err := storage.LoadUnknownList(); err == nil {
            data.UnknownIPs = unknown
        }

        // Cargar listas negra y blanca
        if bl, err := storage.LoadBlacklist(); err == nil {
            data.Blacklist = bl
        }
        if wl, err := storage.LoadWhitelist(); err == nil {
            data.Whitelist = wl
        }

        // Recalcular estado de conexiones en función de listas blanca y negra actuales
        if len(data.Connections) > 0 {
            // mapa rápido de whitelist por IP
            wlSet := make(map[string]struct{})
            for _, ip := range data.Whitelist {
                wlSet[strings.TrimSpace(ip)] = struct{}{}
            }

            for i := range data.Connections {
                c := &data.Connections[i]
                ip := strings.TrimSpace(c.IP)
                proc := strings.TrimSpace(c.Proceso)

                // Prioridad: lista blanca
                if _, ok := wlSet[ip]; ok {
                    c.Estado = "Lista Blanca"
                    continue
                }

                // Luego, verificar lista negra con la misma lógica que el monitor
                for _, bl := range data.Blacklist {
                    if strings.TrimSpace(bl.IP) == ip && (bl.Process == "*" || strings.EqualFold(strings.TrimSpace(bl.Process), proc)) {
                        c.Estado = "Lista Negra"
                        break
                    }
                }
            }
        }

        // Cargar log de texto completo si existe
        if b, err := os.ReadFile(storage.LogFile()); err == nil && len(b) > 0 {
            data.RawLog = string(b)
            // Dividir en sesiones por cada INICIO DEL MONITOREO
            marker := "==================== INICIO DEL MONITOREO ===================="
            parts := strings.Split(data.RawLog, marker)
            var sessions []string
            for _, p := range parts {
                p = strings.TrimSpace(p)
                if p == "" {
                    continue
                }
                // Dividir en líneas y invertir el orden para que las conexiones nuevas aparezcan arriba
                lines := strings.Split(p, "\n")
                // Invertir el orden de las líneas
                for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
                    lines[i], lines[j] = lines[j], lines[i]
                }
                // Reconstruir la sesión con las líneas invertidas
                invertedContent := strings.Join(lines, "\n")
                sess := marker + "\n" + invertedContent
                sessions = append(sessions, sess)
            }
            // Ordenar de más nueva a más vieja (último bloque al principio)
            for i, j := 0, len(sessions)-1; i < j; i, j = i+1, j-1 {
                sessions[i], sessions[j] = sessions[j], sessions[i]
            }
            data.Sessions = sessions
        }

        if err := tpl.Execute(w, data); err != nil {
            log.Printf("Error renderizando plantilla: %v", err)
        }
    })

    // Endpoint ligero para consultar la última actualización de logs
    http.HandleFunc("/last-update", func(w http.ResponseWriter, r *http.Request) {
        paths := []string{storage.LogJSONFile(), storage.LogFile()}
        var latest time.Time
        for _, p := range paths {
            if info, err := os.Stat(p); err == nil {
                if info.ModTime().After(latest) {
                    latest = info.ModTime()
                }
            }
        }
        resp := map[string]int64{"lastUpdate": latest.Unix()}
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(resp)
    })

    log.Println("🌐 Dashboard disponible en http://localhost:8080/")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Printf("Error en servidor HTTP: %v", err)
    }
}
