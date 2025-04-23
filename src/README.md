# Form Service

A simple and secure form submission service built with Go and Gin. This service allows you to collect form submissions from your websites and store them in MongoDB.

## Features

- Secure form submission handling
- CORS protection with configurable allowed origins
- Input validation and sanitization
- Rate limiting
- Request size limiting
- Comprehensive logging
- MongoDB storage

## Prerequisites

- Go 1.21 or later
- MongoDB
- Git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ahi/form-service.git
cd form-service/src
```

2. Install dependencies:
```bash
go mod tidy
```

## Configuration

The service can be configured using either a YAML configuration file or environment variables.

### Configuration File (config.yaml)

Create a `config.yaml` file in the same directory as the executable with the following structure:

```yaml
# Allowed origins for CORS
allowed_origins:
  - "http://localhost:8000"  # For local development
  - "http://example.com"
  - "https://example.com"

# Maximum length for text fields (optional, default: 1000)
max_field_length: 1000
```

### Environment Variables

You can override the allowed origins using the `ALLOWED_ORIGINS` environment variable:

```bash
export ALLOWED_ORIGINS="http://example.com,https://example.com"
```

Note: If both configuration methods are used, the environment variable takes precedence.

## Running the Service

1. Start MongoDB:
```bash
mongod
```

2. Run the service:
```bash
go run main.go
```

The service will start on port 8080 by default.

## API Endpoint

### Submit Form
```
POST /form/:id
```

Parameters:
- `id`: The project ID (MongoDB ObjectId)

Request body (form-urlencoded):
- Any form fields you want to collect

Response:
```json
{
    "message": "Form submitted successfully",
    "projectId": "your-project-id"
}
```

## Security Features

- CORS protection with configurable allowed origins
- Input sanitization to prevent XSS attacks
- Maximum field length to prevent DoS attacks
- Rate limiting (10 requests per minute per IP)
- Request size limiting (1MB)
- Email validation for email fields
- HTML tag removal

## Development

For local development, you can use the included Python server to serve the example form:

```bash
chmod +x serve.sh
./serve.sh
```

This will start a local server on port 8000, serving the example form at `http://localhost:8000/simple-form.html`.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 