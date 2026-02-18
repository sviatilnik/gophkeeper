package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sviatilnik/gophkeeper/internal/auth"
	"github.com/sviatilnik/gophkeeper/internal/server"
	"github.com/sviatilnik/gophkeeper/internal/storage"
)

func main() {
	addr := flag.String("addr", ":8080", "Server address")
	shutdownTimeout := flag.Duration("shutdown-timeout", 30*time.Second, "Timeout for graceful shutdown")
	flag.Parse()

	// Инициализация компонентов
	stor := storage.NewInMemoryStorage()
	tokenManager := auth.NewInMemoryTokenManager(24 * time.Hour)

	// Создание сервера
	srv := server.NewServer(stor, tokenManager)
	srv.RegisterRoutes()

	// Создание HTTP сервера с настройками
	httpServer := &http.Server{
		Addr:         *addr,
		Handler:      nil, // Используется http.DefaultServeMux
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Создание контекста для обработки сигналов завершения
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Запуск сервера в отдельной горутине
	go func() {
		log.Printf("GophKeeper server starting on %s", *addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Ожидание сигнала завершения
	<-ctx.Done()
	log.Println("Shutting down server...")

	// Создание контекста с таймаутом для graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()

	// Graceful shutdown сервера
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
		os.Exit(1)
	}

	log.Println("Server stopped gracefully")
}
