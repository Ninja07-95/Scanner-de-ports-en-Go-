package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Options de configuration
type ScanConfig struct {
	Host         string
	Ports        []int
	Threads      int
	Timeout      time.Duration
	BannerGrab   bool
	OutputFile   string
	Verbose      bool
	ShowClosed   bool
	ScanType     string
	WaitTime     time.Duration
	ServiceProbe bool
}

// Résultat du scan d'un port
type ScanResult struct {
	Port    int
	State   string
	Service string
	Banner  string
	TTL     int
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
	111:   "RPC",
	135:   "MSRPC",
	137:   "NetBIOS-ns",
	138:   "NetBIOS-dgm",
	139:   "NetBIOS-ssn",
	143:   "IMAP",
	161:   "SNMP",
	162:   "SNMP-trap",
	389:   "LDAP",
	443:   "HTTPS",
	445:   "SMB",
	465:   "SMTPS",
	500:   "IKE",
	514:   "Syslog",
	587:   "SMTP",
	631:   "IPP",
	636:   "LDAPS",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	1723:  "PPTP",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	5901:  "VNC-1",
	5985:  "WinRM",
	5986:  "WinRM-HTTPS",
	6379:  "Redis",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9000:  "Portainer",
	9090:  "Prometheus",
	9200:  "Elasticsearch",
	27017: "MongoDB",
	49152: "Windows-RPC",
	49153: "Windows-RPC",
	49154: "Windows-RPC",
}

// Probes de service pour l'identification des services
var serviceProbes = map[int][]byte{
	21:  []byte("QUIT\r\n"),
	22:  []byte("SSH-2.0-OpenSSH_8.2p1\r\n"),
	25:  []byte("EHLO localhost\r\n"),
	80:  []byte("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: SecPort-Scanner/1.0\r\nConnection: close\r\n\r\n"),
	110: []byte("QUIT\r\n"),
	143: []byte("A001 LOGOUT\r\n"),
	443: []byte("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: SecPort-Scanner/1.0\r\nConnection: close\r\n\r\n"),
}

// Couleurs pour la sortie console
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

// fonction principal de scan de port
func scanPort(config *ScanConfig, port int) ScanResult {
	target := fmt.Sprintf("%s:%d", config.Host, port)
	result := ScanResult{Port: port}

	// déterminer le service attendu
	if service, ok := commonPorts[port]; ok {
		result.Service = service
	} else {
		result.Service = "unknown"
	}

	// Scan TCP SYN
	if config.ScanType == "syn" {
		// Cette implémentation va simuler un scan SYN en utilisant une connexion standard
		conn, err := net.DialTimeout("tcp", target, config.Timeout)
		if err != nil {
			result.State = "closed"
			return result
		}
		conn.Close()
		result.State = "open"
	} else {
		// Scan TCP Connect standard
		conn, err := net.DialTimeout("tcp", target, config.Timeout)
		if err != nil {
			result.State = "closed"
			return result
		}
		defer conn.Close()
		result.State = "open"

		// Récupération du TTL (Time To Live)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if f, err := tcpConn.File(); err == nil {
				defer f.Close()
				// go ne fournit pas d'accès direct au TTL mais c'est une approximation
				result.TTL = 64 // valeur par défaut pour linux
			}
		}

		// Récupération de la bannière si demandée
		if config.BannerGrab && result.State == "open" {
			grabBanner(conn, &result, config, port)
		}
	}

	return result
}
// scanner des olages pendant des durées différentes  (pour ne pas se faire cramé si un soc existe)

// Fonction pour récupérer la bannière du service
func grabBanner(conn net.Conn, result *ScanResult, config *ScanConfig, port int) {
	// Définir un délai de lecture
	conn.SetReadDeadline(time.Now().Add(config.Timeout))

	// Envoyer une sonde spécifique au service si disponible
	if config.ServiceProbe {
		if probe, ok := serviceProbes[port]; ok {
			conn.Write(probe)
		}
	}

	// Attendre un peu pour que le serveur réponde
	time.Sleep(config.WaitTime)

	// Lire la réponse
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		result.Banner = "No banner available"
		return
	}

	// Traiter la bannière
	if n > 0 {
		bannerStr := string(buffer[:n])
		// Nettoyer la bannière pour l'affichage
		bannerStr = strings.Replace(bannerStr, "\r", "", -1)
		bannerStr = strings.Replace(bannerStr, "\n", " ", -1)
		if len(bannerStr) > 100 {
			bannerStr = bannerStr[:100] + "..."
		}
		result.Banner = bannerStr
	}

	// Cas spécial pour HTTPS
	if port == 443 {
		conn.Close()
		tlsConn, err := tls.Dial("tcp", config.Host+":443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err == nil {
			defer tlsConn.Close()
			result.Banner = "TLS: " + tlsConn.ConnectionState().ServerName
			// Récupérer les certificats
			if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
				cert := tlsConn.ConnectionState().PeerCertificates[0]
				result.Banner += fmt.Sprintf(" (Issuer: %s, Expires: %s)", 
					cert.Issuer.CommonName, cert.NotAfter.Format("2006-01-02"))
			}
		}
	}
}

// Convertit une chaîne de plage de ports en slice de ports
func parsePortRange(portRange string) ([]int, error) {
	ports := []int{}
	
	// Traiter les ports spéciaux
	if portRange == "common" {
		// Ajouter tous les ports communs de notre map
		for port := range commonPorts {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		return ports, nil
	}
	
	// Séparer les parties de la plage par virgule
	parts := strings.Split(portRange, ",")
	
	for _, part := range parts {
		// Recherche de plage 
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

// Écrire les résultats dans un fichier


func writeResultsToFile(results []ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "# Scan de ports pour %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "# Target: %s\n\n", flag.Lookup("host").Value.String())
	
	fmt.Fprintf(file, "PORT\tSTATE\tSERVICE\tBANNER\n")
	for _, result := range results {
		banner := ""
		if result.Banner != "" {
			banner = result.Banner
		}
		fmt.Fprintf(file, "%d\t%s\t%s\t%s\n", result.Port, result.State, result.Service, banner)
	}
	
	return nil
}

// Le logo 
func displayLogo() {
	logo := `
 _   _ _       _                               _               
| \ | (_)     (_)                             | |              
|  \| | _ _ _  _  __ _ ___    __ _ _ __ ___   | |__   ___ _ __ ___ 
| . . | | '_ \| |/ _' / __|  / _' | '__/ _ \  | '_ \ / _ \ '__/ _ \
| |\  | | | | | | (_| \__ \ | (_| | | |  __/  | | | |  __/ | |  __/
\_| \_/_|_| |_|_|\__,_|___/  \__,_|_|  \___|  |_| |_|\___|_|  \___|
              | /
                                      Let's find some ports "_"
`
	fmt.Println(colorCyan + logo + colorReset)
}
// Gérer les interruptions
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n" + colorRed + "[!] Scan interrompu par l'utilisateur" + colorReset)
		os.Exit(0)
	}()
}

func main() {
	// Définition des flags
	host := flag.String("host", "", "L'hôte à scanner (requis)")
	portRange := flag.String("ports", "1-1024", "Plage de ports à scanner (ex: 80,443,8080-8090 ou 'common')")
	threads := flag.Int("threads", 100, "Nombre de threads concurrents")
	timeout := flag.Duration("timeout", 1*time.Second, "Délai d'attente pour chaque connexion")
	bannerGrab := flag.Bool("banner", false, "Activer la récupération de bannière")
	outputFile := flag.String("output", "", "Fichier de sortie (format texte)")
	verbose := flag.Bool("verbose", false, "Mode verbeux")
	showClosed := flag.Bool("show-closed", false, "Afficher les ports fermés")
	scanType := flag.String("scan-type", "connect", "Type de scan (connect ou syn)")
	waitTime := flag.Duration("wait", 200*time.Millisecond, "Temps d'attente entre l'envoi et la réception pour la récupération de bannière")
	serviceProbe := flag.Bool("service-probe", true, "Envoyer des probes spécifiques aux services")
	flag.Parse()

	// Vérifier les arguments obligatoires
	if *host == "" {
		fmt.Println(colorRed + "Erreur: L'hôte est requis" + colorReset)
		fmt.Println("Utilisation: port-scanner -host example.com -ports 80,443")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Configurer la gestion des interruptions
	setupSignalHandler()

	// Afficher le logo
	displayLogo()

	// Parsing de la plage de ports
	ports, err := parsePortRange(*portRange)
	if err != nil {
		fmt.Printf(colorRed+"Erreur: %v\n"+colorReset, err)
		os.Exit(1)
	}

	// Configuration du scan
	config := &ScanConfig{
		Host:         *host,
		Ports:        ports,
		Threads:      *threads,
		Timeout:      *timeout,
		BannerGrab:   *bannerGrab,
		OutputFile:   *outputFile,
		Verbose:      *verbose,
		ShowClosed:   *showClosed,
		ScanType:     *scanType,
		WaitTime:     *waitTime,
		ServiceProbe: *serviceProbe,
	}

	// Validation du type de scan
	if config.ScanType != "connect" && config.ScanType != "syn" {
		fmt.Println(colorRed + "Erreur: Le type de scan doit être 'connect' ou 'syn'" + colorReset)
		os.Exit(1)
	}

	// Afficher les informations de scan
	fmt.Printf(colorYellow + "\n[*] Configuration du scan" + colorReset + "\n")
	fmt.Printf("    Hôte cible: %s\n", config.Host)
	fmt.Printf("    Plage de ports: %s (%d ports)\n", *portRange, len(ports))
	fmt.Printf("    Threads: %d\n", config.Threads)
	fmt.Printf("    Timeout: %v\n", config.Timeout)
	fmt.Printf("    Type de scan: %s\n", config.ScanType)
	fmt.Printf("    Récupération de bannière: %v\n", config.BannerGrab)

	// Résolution DNS

	fmt.Printf(colorYellow + "\n[*] Résolution DNS" + colorReset + "\n")
	ips, err := net.LookupIP(config.Host)
	if err != nil {
		fmt.Printf(colorRed+"    Erreur de résolution DNS: %v\n"+colorReset, err)
	} else {
		for _, ip := range ips {
			fmt.Printf("    %s -> %s\n", config.Host, ip.String())
		}
	}

	startTime := time.Now()

	// Affichage du début du scan
	fmt.Printf(colorYellow + "\n[*] Début du scan" + colorReset + "\n")

	// Initialisation du waitgroup et des résultats
	var wg sync.WaitGroup
	results := make([]ScanResult, 0)
	resultsMutex := &sync.Mutex{}

	// Création d'un channel pour limiter le nombre des threads
	semaphore := make(chan struct{}, config.Threads)

	// Initialisation des compteurs de ports
	portsOpen := 0
	portsClosed := 0
	portsFiltered := 0

	// Lancement des scans
	for _, port := range config.Ports {
		wg.Add(1)

		go func(p int) {
			defer wg.Done()

			// Acquérir un slot dans le sémaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := scanPort(config, p)

			// Ajuter des résultats à la liste
			resultsMutex.Lock()
			results = append(results, result)
			resultsMutex.Unlock()

			// Mise à jour des compteurs
			switch result.State {
			case "open":
				resultsMutex.Lock()
				portsOpen++
				resultsMutex.Unlock()
				
				// Affichage des ports ouverts
				bannerInfo := ""
				if result.Banner != "" {
					bannerInfo = fmt.Sprintf(" - %s", result.Banner)
				}
				
				fmt.Printf(colorGreen+"[+] Port %-5d ouvert  %-12s"+colorReset+"%s\n", 
					p, "("+result.Service+")", bannerInfo)
			
			case "closed":
				resultsMutex.Lock()
				portsClosed++
				resultsMutex.Unlock()
				
				// Affichage des ports fermés si demandé
				if config.ShowClosed {
					fmt.Printf(colorRed+"[-] Port %-5d fermé  %-12s\n"+colorReset, 
						p, "("+result.Service+")")
				}
			
			case "filtered":
				resultsMutex.Lock()
				portsFiltered++
				resultsMutex.Unlock()
				
				if config.Verbose {
					fmt.Printf(colorYellow+"[?] Port %-5d filtré %-12s\n"+colorReset, 
						p, "("+result.Service+")")
				}
			}
		}(port)
	}

	// Attendre la fin de tous les scans
	wg.Wait()

	// Calcul du temps écoulé
	elapsedTime := time.Since(startTime)

	// Tri des résultats par numéro de port
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Afficher le résumé
	fmt.Printf(colorYellow + "\n[*] Résumé du scan" + colorReset + "\n")
	fmt.Printf("    Temps écoulé: %s\n", elapsedTime)
	fmt.Printf("    Ports ouverts: %d\n", portsOpen)
	fmt.Printf("    Ports fermés: %d\n", portsClosed)
	fmt.Printf("    Ports filtrés: %d\n", portsFiltered)

	// Les résultats dans un fichier 
	if config.OutputFile != "" {
		err := writeResultsToFile(results, config.OutputFile)
		if err != nil {
			fmt.Printf(colorRed+"\n[!] Erreur lors de l'écriture du fichier: %v\n"+colorReset, err)
		} else {
			fmt.Printf(colorGreen+"\n[+] Résultats sauvegardés dans: %s\n"+colorReset, config.OutputFile)
		}
	}

	// Tableau de résultats (les ports ouverts)
	if portsOpen > 0 {
		fmt.Printf(colorYellow + "\n[*] Détails des ports ouverts" + colorReset + "\n")
		fmt.Println("    PORT      STATE       SERVICE      BANNER")
		fmt.Println("    ----      -----       -------      ------")
		for _, result := range results {
			if result.State == "open" {
				banner := ""
				if result.Banner != "" {
					banner = result.Banner
				}
				fmt.Printf("    %-10d %-12s %-12s %s\n", result.Port, result.State, result.Service, banner)
			}
		}
	}

	fmt.Printf(colorYellow + "\n[*] Scan terminé" + colorReset + "\n")
}
