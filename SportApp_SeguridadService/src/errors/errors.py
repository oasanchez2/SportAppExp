class ApiError(Exception):
    code = 422
    description = "Default message"

class UserAlreadyExists(ApiError):
    code = 412
    description = "User with username already exists"

class UserNotFoundError(ApiError):
    code = 404
    description = "User with username and password does not exist"

class IncompleteParams(ApiError):
    code = 400
    description = "Bad request"

class Unauthorized(ApiError):
    code = 401
    description = "Unauthorized"

class ClientExError(ApiError):
    code = 500
    description = "Error"

class ExeptionExError(ApiError):
    code = 500
    description = "Error exeption"

class UserNotConfirmedError(ApiError):
    code = 401
    description = "Usuario no confirmado"

class InvalidPasswordError(ApiError):
    code = 412
    description = "Contraseña no conforme"    

class InvalidEamilError(ApiError):
    code = 412
    description = "Email invalido" 

class ClientInvalidParameterError(ApiError):
    code = 412
    description = "Error de parametros"    

class CodeNotExistsError(ApiError):
    code = 412
    description = "Codigo invalido"

class CodeExpiredError(ApiError):
    code = 412
    description = "Codigo expiro"

class GetUserNotFoundError(ApiError):
    code = 404
    description = "Usuario no encontrado"

class PasswordResetRequiredError(ApiError):
    code = 401
    description = "Por favor cambie su contraseña"

class LimitExceededError(ApiError):
    code = 412
    description = "Supero el limite de intentos. Intente mas tarde"
