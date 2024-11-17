package main

// Features: FIle upload, commnd prebuild, rate limiting, size limiting, fast go code.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/fatih/color"
	"golang.org/x/time/rate"
)

var upload_dir = "./"
var size_limit int = 1000

const logo = `==========================UPLOADER==========================
Free tool for pentesting and CTFs!`

func main() {
	color.Cyan(logo)

	port := flag.Int("p", 8080, "Select a custom port for the file upload server to listen on-")
	upload_dir_pointer := flag.String("o", "./", "Where the files are stored after they are uploaded to the server.")
	upload_path_pointer := flag.String("path", "/", "What should be the path to the server where the file should be uploaded")
	interface_pointer := flag.String("i", "tun0", "Which interface you want to use, so the command builder can build the custom command.")
	file_size_pointer := flag.Int("s", 1000, "What should be the max file size of a file, the default is 1 GB, this is in MB.")

	flag.Parse()

	upload_dir = *upload_dir_pointer
	upload_path := *upload_path_pointer
	size_limit = *file_size_pointer

	if upload_path[0] != byte('/') {
		upload_path = "/" + upload_path
	}

	addr, err := GetInterfaceIpv4Addr(*interface_pointer)

	if err != nil && *interface_pointer != "tun0" {
		color.Red("The interface doesn't exist!")
	}

	limiter := rate.NewLimiter(5, 1)

	server := http.NewServeMux()
	server.HandleFunc(upload_path, uploadHandler)

	rateLimitedHandler := LimitMiddleware(server, limiter)

	color.Green(fmt.Sprintf("Starting Upload-server on port %s..., files are uploaded to %s", strconv.Itoa(*port), upload_dir))

	if *interface_pointer != "tun0" {
		PrintUploadCommands(addr, upload_path, strconv.Itoa(*port))
	}

	if err := http.ListenAndServe(":"+strconv.Itoa(*port)+"", rateLimitedHandler); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
	return
}

func PrintUploadCommands(ip string, path string, port string) {
	fmt.Printf("curl -F \"file=@<your-file-name>\" http://%s:%s%s\n", ip, port, path)
	return
}

// Reference: https://gist.github.com/schwarzeni/f25031a3123f895ff3785970921e962c
func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", errors.New(fmt.Sprintf("interface %s don't have an ipv4 address\n", interfaceName))
	}
	return ipv4Addr.String(), nil
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var i64_size int64
	i64_size = int64(size_limit)
	if err := r.ParseMultipartForm(i64_size << 20); err != nil {
		http.Error(w, fmt.Sprintf("Error parsing form: %v", err), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(handler.Filename)
	savePath := filepath.Join(upload_dir, filename)

	destFile, err := os.Create(savePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating file: %v", err), http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, file); err != nil {
		http.Error(w, fmt.Sprintf("Error saving file: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File uploaded successfully: %s\n", savePath)
}

func LimitMiddleware(next http.Handler, limiter *rate.Limiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
