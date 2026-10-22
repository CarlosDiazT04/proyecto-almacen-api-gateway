# API Gateway

Punto de entrada al backend. Resuelve los servicios mediante Eureka y valida los tokens JWT antes de permitir el acceso a las rutas protegidas.

- Puerto: `8080`
- Variable requerida: `JWT_SECRET`

El valor de `JWT_SECRET` debe coincidir con el configurado en Auth Service.

## Ejecución

```bash
mvn spring-boot:run
```
