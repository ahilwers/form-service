package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
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
	// Default value for MaxFieldLength
	config.MaxFieldLength = 1000

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

func rateLimitMiddleware() gin.HandlerFunc {
	// Simple rate limiting using a map to track IP addresses
	// In production, you might want to use Redis or another distributed solution
	ipRequests := make(map[string]int)
	lastReset := time.Now()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		// Reset counters every minute
		if now.Sub(lastReset) > time.Minute {
			ipRequests = make(map[string]int)
			lastReset = now
		}

		// Allow maximum 10 requests per minute per IP
		if ipRequests[ip] >= 10 {
			logger.WithFields(logrus.Fields{
				"ip": ip,
			}).Warn("Rate limit exceeded")

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		ipRequests[ip]++
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
