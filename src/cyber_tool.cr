require "socket"
require "http/client"
require "option_parser"
require "colorize"

# Estructura para almacenar los resultados del escaneo de puertos
record PortResult, port : UInt16, status : String
init_port = 1_u16
end_port = 0_u16
ip_to_scan = "0.0.0.0"
command = ""
url = ""

# Función para escanear un puerto específico en una IP
def scan_specific_port(ip : String, port : UInt16) : PortResult
  begin
    socket = TCPSocket.new(ip, port, connect_timeout: 10)
    socket.close
    PortResult.new(port, "Abierto".colorize(:green).to_s)
  rescue
    PortResult.new(port, "Cerrado".colorize(:red).to_s)
  end
end

# Función para realizar el escaneo de puertos en paralelo
def port_scan(ip : String, ports_to_scan : Array(UInt16))
  results_channel = Channel(PortResult).new

  puts "Escaneando puertos en #{ip}..."

  ports_to_scan.each do |port|
    spawn do
      results_channel.send(scan_specific_port(ip, port))
    end
  end

  results = (1..ports_to_scan.size).map do
    results_channel.receive
  end

  results.sort_by(&.port).each do |result|
    puts "Puerto #{result.port}: #{result.status}"
  end

  open_ports = results.select { |r| r.status == "Abierto".colorize(:green).to_s }.map(&.port).join(", ")
  puts "\nResumen: los puertos #{open_ports.colorize(:green)} están abiertos."
end

# Función para analizar los encabezados HTTP de una URL
def header_scan(url : String)
  begin
    uri = URI.parse(url)
    response = HTTP::Client.get(uri)

    puts "Encabezados HTTP para #{url}:"
    response.headers.each do |key, value|
      puts "  #{key}: #{value}"
    end
  rescue ex
    puts "Error al obtener los encabezados: #{ex.message}"
  end
end

# Analizador de opciones de línea de comandos
OptionParser.parse do |parser|
  parser.banner = "Uso: cyber_tool [comando] [argumento]"

  parser.on("scan-ports", "Escanea puertos abiertos en una IP") do
    parser.banner = "Uso: cyber_tool scan-ports --ip IP -p PORTS [-i INIT_PORT]"
    command = "scan-ports"

    parser.on("-p", "--ports [PORTS]", "Lista de puertos a escanear") do |ports|
      end_port = ports.to_u16
    end
    parser.on("-I IP", "--ip IP", "Dirección IP a escanear") do |ip|
      if ip =~ /\A\d{1,3}(\.\d{1,3}){3}\z/
        ip_to_scan = ip
      else
        puts "IP inválida. Debe ser del formato x.x.x.x".colorize(:red)
        exit 1
      end
    end
    parser.on("-i", "--init-port [PORT]", "Puerto inicial para el escaneo") do |port|
      init_port = port.to_u16
    end

    
  end

  parser.on("header-scan", "Analiza los encabezados HTTP de una URL") do
    parser.banner = "Uso: cyber_tool header-scan --url URL"
    command = "header-scan"
    parser.on("-u", "--url URL", "URL a analizar") do |u|
      if u =~ /\Ahttps?:\/\/[^\s]+\z/
        url = u
      else
        puts "URL inválida. Debe comenzar con http:// o https://"
        exit 1
      end
    end

    

  end

  parser.on("-h", "--help", "Muestra esta ayuda") do
    puts parser
    exit
  end
end

case command
when "scan-ports"
  if init_port < 1 || end_port < init_port
    puts "Los puertos deben ser mayores que 0 y el puerto final debe ser mayor o igual al inicial.".colorize(:red)
    exit 1
  end
  end_port = end_port == 0 ? 65535_u16 : end_port

  port_scan(ip_to_scan, (init_port..end_port).to_a)
when "header-scan"
  if url.empty?
    puts "Debe proporcionar una URL para el escaneo de encabezados.".colorize(:red)
    exit 1
  end
  header_scan(url)
else
  puts "Comando no reconocido. Use --help para ver las opciones disponibles.".colorize(:red)
  exit 1
end
