package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Résultat du scan d'un port
type ScanResult struct {
	Port    int
	State   bool
	Service string
}

// Services communs associés aux ports
var commonPorts = map[int]string{
	20:    "FTP-data",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	465:   "SMTPS",
	587:   "SMTP",
	993:   "IMAPS",
	995:   "POP3S",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
}

// Vérifie si un port est ouvert
func scanPort(host string, port int, timeout time.Duration) ScanResult {
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	
	result := ScanResult{Port: port}
	
	if err != nil {
		result.State = false
		return result
	}
	
	defer conn.Close()
	result.State = true
	
	// Identifier le service si connu
	if service, ok := commonPorts[port]; ok {
		result.Service = service
	}
	
	return result
}

// Convertit une chaîne de plage de ports en slice de ports
func parsePortRange(portRange string) ([]int, error) {
	ports := []int{}
	
	// Séparer les parties de la plage par virgule
	parts := strings.Split(portRange, ",")
	
	for _, part := range parts {
		// Recherche de plage (exemple: 80-100)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("format de plage invalide: %s", part)
			}
			
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("port de début invalide: %s", rangeParts[0])
			}
			
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("port de fin invalide: %s", rangeParts[1])
			}
			
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// Port unique
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("port invalide: %s", part)
			}
			ports = append(ports, port)
		}
	}
	
	return ports, nil
}

func main() {
	// Définition des flags
	host := flag.String("host", "localhost", "L'hôte à scanner")
	portRange := flag.String("ports", "1-1024", "Plage de ports à scanner (ex: 80,443,8080-8090)")
	threads := flag.Int("threads", 100, "Nombre de threads concurrents")
	timeout := flag.Duration("timeout", 500*time.Millisecond, "Délai d'attente pour chaque connexion")
	flag.Parse()
	
	// Vérification de l'adresse IP/domaine
	if *host == "" {
		fmt.Println("Erreur: Veuillez spécifier un hôte")
		os.Exit(1)
	}
	
	// Parsing de la plage de ports
	ports, err := parsePortRange(*portRange)
	if err != nil {
		fmt.Printf("Erreur: %v\n", err)
		os.Exit(1)
	}
	
	// Affichage des informations de scan
	fmt.Printf("\n[*] Début du scan de %s\n", *host)
	fmt.Printf("[*] Plage de ports: %s (%d ports)\n", *portRange, len(ports))
	fmt.Printf("[*] Threads: %d\n", *threads)
	fmt.Printf("[*] Timeout: %v\n\n", *timeout)
	
	startTime := time.Now()
	
	// Initialisation du waitgroup et des résultats
	var wg sync.WaitGroup
	results := make([]ScanResult, 0)
	resultsMutex := &sync.Mutex{}
	
	// Création d'un channel pour limiter le nombre de threads
	semaphore := make(chan struct{}, *threads)
	
	// Lancement des scans
	for _, port := range ports {
		wg.Add(1)
		
		go func(p int) {
			defer wg.Done()
			
			// Acquérir un slot dans le sémaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result := scanPort(*host, p, *timeout)
			
			if result.State {
				resultsMutex.Lock()
				results = append(results, result)
				resultsMutex.Unlock()
				
				serviceInfo := ""
				if result.Service != "" {
					serviceInfo = fmt.Sprintf(" - %s", result.Service)
				}
				
				fmt.Printf("[+] Port %d ouvert%s\n", p, serviceInfo)
			}
		}(port)
	}
	
	// Attente de la fin de tous les scans
	wg.Wait()
	
	// Tri des résultats par numéro de port
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	
	// Affichage du résumé
	fmt.Printf("\n[*] Scan terminé en %s\n", time.Since(startTime))
	fmt.Printf("[*] %d ports ouverts sur %d ports scannés\n\n", len(results), len(ports))
	
	// Affichage du tableau de résultats
	if len(results) > 0 {
		fmt.Println("PORT\tSTATE\tSERVICE")
		fmt.Println("----\t-----\t-------")
		for _, result := range results {
			service := result.Service
			if service == "" {
				service = "unknown"
			}
			fmt.Printf("%d\topen\t%s\n", result.Port, service)
		}
	} else {
		fmt.Println("Aucun port ouvert détecté.")
	}
}
