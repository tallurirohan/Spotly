# Spotly - Event Management Platform

A modern event management platform with venue management, ticket booking, and retro-style ticket generation.

## Features

- **User Roles**: Audience, Creators, Venue Managers
- **Event Management**: Create, manage, and track events
- **Venue Management**: List and manage venues with booking requests
- **Ticket System**: Beautiful retro-style ticket generation
- **Booking System**: Complete booking flow with payment integration
- **Responsive Design**: Modern glassmorphism UI with mobile support

## Quick Start

### Development

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd Spotly
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run Development Server**
   ```bash
   python app.py
   ```
   Visit http://localhost:5000

### Production Deployment

1. **Environment Setup**
   ```bash
   export FLASK_ENV=production
   export SECRET_KEY=your-secure-secret-key
   export PORT=5000
   ```

2. **Install Production Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run with Gunicorn**
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

## Security Features

- **Input Validation**: Comprehensive validation for all user inputs
- **Password Requirements**: Strong password enforcement
- **Rate Limiting**: Protection against brute force attacks
- **Security Headers**: XSS, CSRF, and clickjacking protection
- **SQL Injection Prevention**: Parameterized queries throughout
- **File Upload Security**: Safe file handling with type validation

## API Endpoints

### Authentication
- `POST /signup` - User registration
- `POST /login` - User login
- `GET /logout` - User logout

### Events
- `GET /events/<id>` - View event details
- `POST /creator/events` - Create event (creator only)
- `POST /book/<event_id>` - Book event (audience only)

### Venues
- `GET /creator/venues` - Browse venues (creator only)
- `POST /venuehub/venues` - Create venue (venue manager only)
- `POST /creator/venues/<id>/request` - Request venue booking

### Tickets
- `GET /booking/<id>/ticket` - View retro ticket
- `GET /booking/<id>/confirmation` - Booking confirmation

## Database Schema

The application uses SQLite with the following tables:
- `users` - User accounts and roles
- `events` - Event listings
- `bookings` - Event bookings
- `venues` - Venue listings
- `venue_bookings` - Venue booking requests

## Configuration

### Environment Variables
- `FLASK_ENV` - Development or production mode
- `SECRET_KEY` - Flask secret key (required in production)
- `PORT` - Server port (default: 5000)
- `DATABASE_URL` - Database connection string
- `MAX_CONTENT_LENGTH` - Maximum file upload size

### Security Headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy: Strict CSP policy

## Monitoring & Logging

- **Log File**: `spotly.log`
- **Log Level**: Configurable (INFO, WARNING, ERROR)
- **Error Handling**: Comprehensive error pages and logging
- **Rate Limiting**: Tracks and limits suspicious activity

## Deployment Options

### Heroku
```bash
heroku create spotly-app
heroku config:set FLASK_ENV=production SECRET_KEY=your-key
git push heroku main
```

### Docker
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

### DigitalOcean/AWS
- Use the provided production configuration
- Set up reverse proxy with Nginx
- Configure SSL certificates
- Set up monitoring and backups

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- Check the error logs in `spotly.log`
- Review the troubleshooting section
- Create an issue on GitHub

## Troubleshooting

### Common Issues

1. **Database Errors**: Ensure SQLite file permissions are correct
2. **Upload Issues**: Check upload directory permissions
3. **Rate Limiting**: Wait 1 minute between login attempts
4. **Template Errors**: Ensure all templates are present

### Performance Tips

- Use production WSGI server (Gunicorn)
- Enable database indexing
- Optimize file uploads
- Monitor memory usage

---

**Version**: 1.0.0  
**Last Updated**: 2025-04-19
