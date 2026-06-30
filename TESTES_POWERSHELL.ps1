# 1) Healthcheck
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health"

# 2) Registrar escritório
$body = @{
  nome = "Escritório Modelo"
  email = "admin@advogoseguro.com.br"
  senha = "123456"
  cnpj = "00000000000100"
} | ConvertTo-Json
$res = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/escritorio/registro" -Method POST -ContentType "application/json" -Body $body
$res
$token = $res.token

# 3) Criar advogado
$headers = @{ Authorization = "Bearer $token" }
$adv = @{
  nome = "Dra. Ana Silva"
  oab = "DF 12345"
  telefone_oficial = "61999998888"
  foto_url = ""
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/escritorio/advogados" -Method POST -ContentType "application/json" -Headers $headers -Body $adv

# 4) Listar advogados
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/escritorio/advogados" -Headers $headers
