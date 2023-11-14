
import socket

def cifrar_des(clave, texto_plano):
    # Función de cifrado DES (mismo código que antes)
    texto_cifrado = b""
    for i in range(0, len(texto_plano), 8):
        bloque = texto_plano[i:i + 8]
        while len(bloque) < 8:
            bloque += b'\0'  # Relleno con bytes nulos
        texto_cifrado += xor_bytes(bloque, clave)
    return texto_cifrado

def xor_bytes(a, b):
    # Función de operación XOR byte a byte
    return bytes(map(lambda x, y: x ^ y, a, b))

def generar_clave_diffie_hellman(socket_cliente):
    # Protocolo de intercambio de claves Diffie-Hellman
    p = int(input("Ingrese variable p(Numero primo):"))  # Número primo compartido
    g = int(input("Ingrese variable g:"))  # Generador

    # Recibir A del cliente
    A = int(socket_cliente.recv(1024).decode())

    # Seleccionar un número secreto aleatorio
    b = 15
    B = (g**b) % p

    # Enviar B al cliente
    socket_cliente.send(str(B).encode())

    # Calcular la clave compartida
    clave_compartida = (A**b) % p

    return str(clave_compartida).encode()

def main():
    # Crear un socket para el servidor
    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Asociar el socket al puerto 12345 y escuchar conexiones entrantes
    socket_servidor.bind(('localhost', 12345))
    socket_servidor.listen()

    print("Esperando conexión...")
    # Aceptar la conexión del cliente y obtener el socket del cliente y su dirección
    socket_cliente, direccion = socket_servidor.accept()
    print(f"Conexión establecida con {direccion}")

    # Realizar el intercambio de claves Diffie-Hellman
    clave_diffie_hellman = generar_clave_diffie_hellman(socket_cliente)
    print(f"Clave Diffie Hellman: {clave_diffie_hellman}")

    # Recibir la clave DES del cliente
    clave_des = socket_cliente.recv(8)

    # Recibir el mensaje encriptado desde el cliente
    mensaje_encriptado = socket_cliente.recv(1024)
    print(f"mensaje encriptado: {mensaje_encriptado}")
    # Desencriptar el mensaje utilizando la clave generada y la función DES
    mensaje_desencriptado = cifrar_des(clave_des, mensaje_encriptado)

    print(f"mensaje desencriptado: {mensaje_desencriptado}")

    # Guardar el mensaje desencriptado en el archivo 'mensajerecibido.txt'
    with open('mensajerecibido.txt', 'wb') as archivo:
        archivo.write(mensaje_desencriptado)

    print("Mensaje desencriptado y guardado en 'mensajerecibido.txt'")

    # Cerrar los sockets del cliente y del servidor
    socket_cliente.close()
    socket_servidor.close()

# Llamar a la función principal
main()
