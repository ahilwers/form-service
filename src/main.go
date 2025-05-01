package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/yaml.v3"
)

type FormSubmission struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty"`
	ProjectID primitive.ObjectID     `bson:"projectId"`
	Content   map[string]interface{} `bson:"content"`
	CreatedAt time.Time              `bson:"createdAt"`
	IP        string                 `bson:"ip"`
}

// Config holds the service configuration
type Config struct {
	AllowedOrigins []string `yaml:"allowed_origins"`
	MaxFieldLength int      `yaml:"max_field_length"`
	Auth           struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"auth"`
	RateLimit      struct {
		Requests        int     `yaml:"requests"`        // Max requests per period
		Period          int     `yaml:"period"`          // Period in seconds
		Burst           int     `yaml:"burst"`           // Max burst size
		GlobalRequests  int     `yaml:"global_requests"` // Global requests per period
		IPBlockDuration int     `yaml:"ip_block_duration"` // Duration to block IPs in minutes
	} `yaml:"rate_limit"`
}

var (
	client     *mongo.Client
	collection *mongo.Collection
	logger     = logrus.New()
	config     Config

	// Regular expressions for validation
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// loadConfig loads configuration from file and environment variables
func loadConfig() error {
	// Default values
	config.MaxFieldLength = 1000
	
	// Default rate limit settings
	config.RateLimit.Requests = 15        // 15 requests
	config.RateLimit.Period = 60          // per 60 seconds
	config.RateLimit.Burst = 5            // max 5 in burst
	config.RateLimit.GlobalRequests = 100 // 100 requests per minute globally
	config.RateLimit.IPBlockDuration = 30 // Block IPs for 30 minutes

	// Try to load configuration file
	if configFile, err := os.ReadFile("config.yaml"); err == nil {
		if err := yaml.Unmarshal(configFile, &config); err != nil {
			return fmt.Errorf("failed to parse config file: %v", err)
		}
	} else {
		return fmt.Errorf("config file not found: %v", err)
	}

	// Check for environment variables
	if envOrigins := os.Getenv("ALLOWED_ORIGINS"); envOrigins != "" {
		config.AllowedOrigins = strings.Split(envOrigins, ",")
	}
	if envUsername := os.Getenv("AUTH_USERNAME"); envUsername != "" {
		config.Auth.Username = envUsername
	}
	if envPassword := os.Getenv("AUTH_PASSWORD"); envPassword != "" {
		config.Auth.Password = envPassword
	}

	// Validate required auth configuration
	if config.Auth.Username == "" || config.Auth.Password == "" {
		return fmt.Errorf("basic auth credentials are required. Please set them in config.yaml or via AUTH_USERNAME and AUTH_PASSWORD environment variables")
	}

	return nil
}

func init() {
	// Configure logger
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load configuration
	if err := loadConfig(); err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}
}

func main() {
	// Initialize MongoDB connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to MongoDB")
	}
	defer client.Disconnect(ctx)

	// Initialize collection
	collection = client.Database("formservice").Collection("submissions")

	// Log CORS configuration
	logger.WithFields(logrus.Fields{
		"allowed_origins":  config.AllowedOrigins,
		"max_field_length": config.MaxFieldLength,
	}).Info("Service configuration loaded")

	// Initialize Gin router
	r := gin.Default()

	// Configure CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     config.AllowedOrigins,
		AllowMethods:     []string{"POST"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Add security middlewares
	r.Use(rateLimitMiddleware())
	r.Use(loggingMiddleware())
	r.Use(maxSizeMiddleware(1024 * 1024))

	// Define routes
	r.POST("/form/:id", handleFormSubmission)
	r.GET("/data/:id", basicAuthMiddleware(), handleDataExport)

	// Start server
	logger.Info("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		logger.WithError(err).Fatal("Failed to start server")
	}
}

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Process request
		c.Next()

		// Log after request is processed
		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()

		logger.WithFields(logrus.Fields{
			"status":     status,
			"latency":    latency,
			"client_ip":  clientIP,
			"method":     method,
			"path":       path,
			"user_agent": c.Request.UserAgent(),
		}).Info("Request processed")
	}
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	Tokens         float64   // Current number of tokens
	Capacity       float64   // Maximum capacity of tokens
	RefillRate     float64   // Tokens per second to refill
	LastRefillTime time.Time // Last time tokens were refilled
	LastRequestTime time.Time // Last time a request was made
	RequestCount   int       // Count of requests in current period
	ViolationCount int       // Count of rate limit violations
	Blocked        bool      // Whether this IP is blocked
	BlockedUntil   time.Time // When the IP block expires
}

// RateLimiter manages rate limiting for different IPs
type RateLimiter struct {
	Buckets         map[string]*TokenBucket
	Mu              sync.RWMutex
	CleanupTimer    *time.Ticker
	GlobalBucket    *TokenBucket // For global rate limiting
	SuspiciousIPs   map[string]int // Track potentially malicious IPs
	BlockedUserAgents []string    // List of blocked user agents
	RequestPatterns map[string]int // Track suspicious request patterns
}

// Global rate limiter instance
var rateLimiter *RateLimiter

// initRateLimiter initializes the rate limiter
func initRateLimiter() *RateLimiter {
	r := &RateLimiter{
		Buckets:         make(map[string]*TokenBucket),
		CleanupTimer:    time.NewTicker(10 * time.Minute),
		SuspiciousIPs:   make(map[string]int),
		BlockedUserAgents: []string{
			"bot", "crawl", "spider", "scan", // Common bot signatures
			"python-requests", "Go-http-client", // Common script signatures
			"curl", "wget", // Common CLI tools
		},
		RequestPatterns: make(map[string]int),
	}

	// Initialize global bucket
	r.GlobalBucket = &TokenBucket{
		Tokens:        float64(config.RateLimit.GlobalRequests),
		Capacity:      float64(config.RateLimit.GlobalRequests),
		RefillRate:    float64(config.RateLimit.GlobalRequests) / float64(config.RateLimit.Period),
		LastRefillTime: time.Now(),
	}

	// Start cleanup goroutine to prevent memory leaks
	go func() {
		for range r.CleanupTimer.C {
			r.cleanup()
		}
	}()

	return r
}

// cleanup removes buckets that haven't been used in a while
func (r *RateLimiter) cleanup() {
	r.Mu.Lock()
	defer r.Mu.Unlock()

	now := time.Now()
	threshold := now.Add(-30 * time.Minute)
	for ip, bucket := range r.Buckets {
		// Keep blocked IPs in memory until their block expires
		if bucket.Blocked && bucket.BlockedUntil.After(now) {
			continue
		}
		
		// Remove old entries
		if bucket.LastRefillTime.Before(threshold) && !bucket.Blocked {
			delete(r.Buckets, ip)
		}
		
		// Unblock IPs whose block has expired
		if bucket.Blocked && bucket.BlockedUntil.Before(now) {
			bucket.Blocked = false
			logger.WithField("ip", ip).Info("IP block expired")
		}
	}
	
	// Clean up suspicious IPs tracking
	for ip, _ := range r.SuspiciousIPs {
		if _, exists := r.Buckets[ip]; !exists {
			delete(r.SuspiciousIPs, ip)
		}
	}
	
	logger.Info("Rate limiter cleanup completed")
}

// isUserAgentBlocked checks if the user agent should be blocked
func (r *RateLimiter) isUserAgentBlocked(userAgent string) bool {
	userAgent = strings.ToLower(userAgent)
	for _, blocked := range r.BlockedUserAgents {
		if strings.Contains(userAgent, blocked) {
			return true
		}
	}
	return false
}

// Allow checks if a request is allowed and consumes a token if it is
func (r *RateLimiter) Allow(c *gin.Context) bool {
	r.Mu.Lock()
	defer r.Mu.Unlock()

	ip := c.ClientIP()
	userAgent := c.Request.UserAgent()
	path := c.Request.URL.Path
	now := time.Now()
	
	// Check if user agent is blocked
	if r.isUserAgentBlocked(userAgent) {
		logger.WithFields(logrus.Fields{
			"ip": ip,
			"user_agent": userAgent,
		}).Warn("Blocked user agent detected")
		return false
	}
	
	// Track request patterns (e.g., same path from different IPs)
	patternKey := path + "_" + userAgent
	r.RequestPatterns[patternKey]++
	
	// Check for suspicious pattern (many requests to same path with same user agent)
	if r.RequestPatterns[patternKey] > 100 {
		logger.WithFields(logrus.Fields{
			"pattern": patternKey,
			"count": r.RequestPatterns[patternKey],
		}).Warn("Suspicious request pattern detected")
	}

	// Check global rate limit first
	elapsed := now.Sub(r.GlobalBucket.LastRefillTime).Seconds()
	r.GlobalBucket.LastRefillTime = now
	r.GlobalBucket.Tokens = math.Min(
		r.GlobalBucket.Capacity, 
		r.GlobalBucket.Tokens+(elapsed*r.GlobalBucket.RefillRate),
	)
	
	if r.GlobalBucket.Tokens < 1 {
		logger.Warn("Global rate limit exceeded")
		return false
	}

	// Create a new bucket if it doesn't exist
	bucket, exists := r.Buckets[ip]
	if !exists {
		bucket = &TokenBucket{
			Tokens:         float64(config.RateLimit.Burst),
			Capacity:       float64(config.RateLimit.Requests),
			RefillRate:     float64(config.RateLimit.Requests) / float64(config.RateLimit.Period),
			LastRefillTime: now,
			LastRequestTime: now,
		}
		r.Buckets[ip] = bucket
	}
	
	// Check if IP is blocked
	if bucket.Blocked {
		if now.Before(bucket.BlockedUntil) {
			return false
		} else {
			// Unblock if block duration has passed
			bucket.Blocked = false
			bucket.ViolationCount = 0
		}
	}

	// Check for request rate (requests per second)
	requestInterval := now.Sub(bucket.LastRequestTime).Seconds()
	bucket.LastRequestTime = now
	
	// If requests are coming too fast (more than 1 per second), mark as suspicious
	if requestInterval < 1.0 {
		r.SuspiciousIPs[ip]++
		
		// If consistently suspicious, reduce tokens more aggressively
		if r.SuspiciousIPs[ip] > 5 {
			bucket.Tokens -= 2 // Penalize suspicious behavior
			logger.WithField("ip", ip).Warn("Suspicious rapid requests detected")
		}
	}

	// Refill tokens based on time elapsed
	elapsed = now.Sub(bucket.LastRefillTime).Seconds()
	bucket.LastRefillTime = now
	bucket.Tokens = math.Min(bucket.Capacity, bucket.Tokens+(elapsed*bucket.RefillRate))

	// Check if we have enough tokens
	if bucket.Tokens < 1 {
		// Increment violation count
		bucket.ViolationCount++
		
		// If too many violations, block the IP
		if bucket.ViolationCount >= 3 {
			bucket.Blocked = true
			bucket.BlockedUntil = now.Add(time.Duration(config.RateLimit.IPBlockDuration) * time.Minute)
			logger.WithFields(logrus.Fields{
				"ip": ip,
				"blocked_until": bucket.BlockedUntil,
			}).Warn("IP blocked due to repeated violations")
		}
		
		return false
	}

	// Consume tokens (use more tokens for suspicious IPs)
	tokensToConsume := 1.0
	if r.SuspiciousIPs[ip] > 10 {
		tokensToConsume = 2.0
	}
	
	bucket.Tokens -= tokensToConsume
	r.GlobalBucket.Tokens--
	return true
}

// GetRemainingTokens returns the number of tokens remaining for an IP
func (r *RateLimiter) GetRemainingTokens(ip string) float64 {
	r.Mu.RLock()
	defer r.Mu.RUnlock()

	bucket, exists := r.Buckets[ip]
	if !exists {
		return float64(config.RateLimit.Burst)
	}
	
	if bucket.Blocked {
		return 0
	}
	
	return bucket.Tokens
}

// GetBlockedUntil returns when an IP will be unblocked
func (r *RateLimiter) GetBlockedUntil(ip string) *time.Time {
	r.Mu.RLock()
	defer r.Mu.RUnlock()

	bucket, exists := r.Buckets[ip]
	if !exists || !bucket.Blocked {
		return nil
	}
	
	return &bucket.BlockedUntil
}

func rateLimitMiddleware() gin.HandlerFunc {
	// Initialize rate limiter if not already done
	if rateLimiter == nil {
		rateLimiter = initRateLimiter()
	}

	return func(c *gin.Context) {
		// Skip rate limiting for certain paths if needed
		// if c.Request.URL.Path == "/some-unrestricted-path" {
		//     c.Next()
		//     return
		// }

		// Check if the request is allowed
		if !rateLimiter.Allow(c) {
			ip := c.ClientIP()
			remaining := rateLimiter.GetRemainingTokens(ip)
			
			// Check if IP is blocked
			blockedUntil := rateLimiter.GetBlockedUntil(ip)
			if blockedUntil != nil {
				logger.WithFields(logrus.Fields{
					"ip":        ip,
					"blocked_until": blockedUntil.Format(time.RFC3339),
				}).Warn("Blocked IP attempted request")

				c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", config.RateLimit.Requests))
				c.Header("X-RateLimit-Remaining", "0")
				c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", blockedUntil.Unix()))
				c.Header("Retry-After", fmt.Sprintf("%d", int(blockedUntil.Sub(time.Now()).Seconds())))
				
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Access temporarily blocked due to excessive requests",
					"blocked_until": blockedUntil.Format(time.RFC3339),
				})
				c.Abort()
				return
			}

			// For normal rate limiting (not blocked)
			resetTime := time.Now().Add(time.Second * time.Duration(config.RateLimit.Period))
			if remaining > 0 {
				// Calculate when the next token will be available
				resetTime = time.Now().Add(time.Duration(1/float64(config.RateLimit.Requests/config.RateLimit.Period)) * time.Second)
			}
			
			logger.WithFields(logrus.Fields{
				"ip":        ip,
				"remaining": remaining,
				"reset":     resetTime.Format(time.RFC3339),
			}).Warn("Rate limit exceeded")

			// Set rate limit headers
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", config.RateLimit.Requests))
			c.Header("X-RateLimit-Remaining", fmt.Sprintf("%.1f", remaining))
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))
			c.Header("Retry-After", fmt.Sprintf("%d", int(resetTime.Sub(time.Now()).Seconds())))
			
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Please try again later.",
				"retry_after": int(resetTime.Sub(time.Now()).Seconds()),
			})
			c.Abort()
			return
		}

		// Set rate limit headers for successful requests too
		ip := c.ClientIP()
		remaining := rateLimiter.GetRemainingTokens(ip)
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", config.RateLimit.Requests))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%.1f", remaining))
		
		c.Next()
	}
}

// maxSizeMiddleware limits the size of the request body
func maxSizeMiddleware(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only check POST requests
		if c.Request.Method == "POST" {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)

			// Check if the request body is too large
			if c.Request.ContentLength > maxSize {
				logger.WithFields(logrus.Fields{
					"size": c.Request.ContentLength,
					"max":  maxSize,
					"ip":   c.ClientIP(),
				}).Warn("Request body too large")

				c.JSON(http.StatusRequestEntityTooLarge, gin.H{
					"error": "Request body too large",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// validateContent checks for suspicious content
func validateContent(content map[string]interface{}) bool {
	for _, value := range content {
		strValue, ok := value.(string)
		if !ok {
			continue
		}
		// Check for common spam patterns
		if strings.Contains(strings.ToLower(strValue), "http://") ||
			strings.Contains(strings.ToLower(strValue), "https://") ||
			strings.Contains(strings.ToLower(strValue), "www.") ||
			strings.Contains(strings.ToLower(strValue), ".com") {
			return false
		}
	}
	return true
}

// sanitizeInput removes potentially harmful characters and truncates long strings
func sanitizeInput(input string) string {
	// Remove HTML tags
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")

	// Truncate string to maximum length
	if len(input) > config.MaxFieldLength {
		input = input[:config.MaxFieldLength]
	}

	return input
}

// validateInput checks input data for validity
func validateInput(key, value string) (string, bool) {
	// Sanitize input
	value = sanitizeInput(value)

	// Special validation for email fields
	if strings.Contains(strings.ToLower(key), "email") {
		if !emailRegex.MatchString(value) {
			return "", false
		}
	}

	// Check for empty strings after sanitization
	if strings.TrimSpace(value) == "" {
		return "", false
	}

	return value, true
}

func handleFormSubmission(c *gin.Context) {
	projectIDStr := c.Param("id")
	if projectIDStr == "" {
		logger.WithField("error", "empty project id").Warn("Invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Project ID is required"})
		return
	}

	// Validate and convert project ID to ObjectId
	projectID, err := primitive.ObjectIDFromHex(projectIDStr)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err,
			"id":    projectIDStr,
		}).Warn("Invalid project ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID format"})
		return
	}

	// Get form data
	formData := make(map[string]interface{})
	if err := c.Request.ParseForm(); err != nil {
		logger.WithError(err).Warn("Failed to parse form data")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data"})
		return
	}

	// Validate and sanitize form data
	for key, values := range c.Request.PostForm {
		if len(values) > 0 {
			value, valid := validateInput(key, values[0])
			if !valid {
				logger.WithFields(logrus.Fields{
					"field": key,
					"value": values[0],
				}).Warn("Invalid input detected")
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input in field: " + key})
				return
			}
			formData[key] = value
		}
	}

	// Validate content for suspicious patterns
	if !validateContent(formData) {
		logger.WithFields(logrus.Fields{
			"id":      projectIDStr,
			"content": formData,
		}).Warn("Suspicious content detected")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Suspicious content detected"})
		return
	}

	submission := FormSubmission{
		ProjectID: projectID,
		Content:   formData,
		CreatedAt: time.Now(),
		IP:        c.ClientIP(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = collection.InsertOne(ctx, submission)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err,
			"id":    projectIDStr,
		}).Error("Failed to save submission")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save submission"})
		return
	}

	logger.WithFields(logrus.Fields{
		"id": projectIDStr,
	}).Info("Form submission successful")

	c.JSON(http.StatusOK, gin.H{
		"message":   "Form submitted successfully",
		"projectId": projectIDStr,
	})
}

// basicAuthMiddleware handles basic authentication
func basicAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, password, ok := c.Request.BasicAuth()
		if !ok {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if username != config.Auth.Username || password != config.Auth.Password {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Next()
	}
}

// handleDataExport handles the data export endpoint
func handleDataExport(c *gin.Context) {
	projectIDStr := c.Param("id")
	format := c.DefaultQuery("format", "json")

	// Validate project ID
	projectID, err := primitive.ObjectIDFromHex(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
		return
	}

	// Validate format
	if format != "json" && format != "csv" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format. Use 'json' or 'csv'"})
		return
	}

	// Query MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{"projectId": projectID})
	if err != nil {
		logger.WithError(err).Error("Failed to query submissions")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query submissions"})
		return
	}
	defer cursor.Close(ctx)

	var submissions []FormSubmission
	if err = cursor.All(ctx, &submissions); err != nil {
		logger.WithError(err).Error("Failed to decode submissions")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode submissions"})
		return
	}

	// Extract content from submissions
	var contents []map[string]interface{}
	for _, submission := range submissions {
		contents = append(contents, submission.Content)
	}

	// Return data in requested format
	switch format {
	case "json":
		c.JSON(http.StatusOK, contents)
	case "csv":
		if len(contents) == 0 {
			c.String(http.StatusOK, "")
			return
		}

		// Get all unique keys
		keys := make(map[string]bool)
		for _, content := range contents {
			for key := range content {
				keys[key] = true
			}
		}

		// Create CSV header
		header := make([]string, 0, len(keys))
		for key := range keys {
			header = append(header, key)
		}

		// Write CSV
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=export.csv")
		writer := csv.NewWriter(c.Writer)
		writer.Write(header)

		// Write data rows
		for _, content := range contents {
			row := make([]string, len(header))
			for i, key := range header {
				if value, ok := content[key]; ok {
					row[i] = fmt.Sprintf("%v", value)
				}
			}
			writer.Write(row)
		}
		writer.Flush()
	}
}
