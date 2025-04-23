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
- Data export in JSON and CSV formats
- Mandatory Basic authentication for data access

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

# Basic Auth configuration (required)
auth:
  username: "admin"
  password: "secret"
```

### Environment Variables

You can override the configuration using environment variables:

```bash
# Override allowed origins
export ALLOWED_ORIGINS="http://example.com,https://example.com"

# Override basic auth credentials
export AUTH_USERNAME="admin"
export AUTH_PASSWORD="secret"
```

Note: If both configuration methods are used, the environment variables take precedence.

Important: Basic Auth credentials are mandatory. The service will not start without them.

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

## API Endpoints

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

### Export Data
```
GET /data/:id?format=json|csv
```

Parameters:
- `id`: The project ID (MongoDB ObjectId)
- `format`: Output format (json or csv, defaults to json)

Authentication:
- Basic Auth required
- Username and password must be set in config.yaml or via environment variables

Response (JSON):
```json
[
  {
    "field1": "value1",
    "field2": "value2"
  },
  {
    "field1": "value3",
    "field2": "value4"
  }
]
```

Response (CSV):
```csv
field1,field2
value1,value2
value3,value4
```

## Security Features

- CORS protection with configurable allowed origins
- Input sanitization to prevent XSS attacks
- Maximum field length to prevent DoS attacks
- Rate limiting (10 requests per minute per IP)
- Request size limiting (1MB)
- Email validation for email fields
- HTML tag removal
- Mandatory Basic authentication for data access

## Development

For local development, you can use the included Python server to serve the example form:

```bash
chmod +x serve.sh
./serve.sh
```

This will start a local server on port 8000, serving the example form at `http://localhost:8000/simple-form.html`.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 