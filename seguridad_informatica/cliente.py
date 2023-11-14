
import socket
from os import urandom

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

    # Seleccionar un número secreto aleatorio
    a = 6
    A = (g**a) % p

    # Enviar A al servidor
    socket_cliente.send(str(A).encode())

    # Recibir B del servidor
    B = int(socket_cliente.recv(1024).decode())

    # Calcular la clave compartida
    clave_compartida = (B**a) % p

    return str(clave_compartida).encode()

def main():
    # Crear un socket para el cliente
    socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Conectar al servidor en el puerto 12345
    socket_cliente.connect(('localhost', 12345))

    # Realizar el intercambio de claves Diffie-Hellman
    clave_diffie_hellman = generar_clave_diffie_hellman(socket_cliente)
    print(f"Clave Diffie Hellman: {clave_diffie_hellman}")

    # Generar una clave secreta aleatoria de 8 bytes para DES
    clave_des = urandom(8)

    # Enviar la clave DES al servidor
    socket_cliente.send(clave_des)

    # Leer el mensaje desde el archivo 'mensajeentrada.txt'
    with open('mensajeentrada.txt', 'rb') as archivo:  #lectura y escritura binaria
        mensaje = archivo.read()
    archivo.close()

    # Encriptar el mensaje utilizando la clave generada y la función DES
    mensaje_encriptado = cifrar_des(clave_des, mensaje)
    print(mensaje_encriptado)

    # Enviar el mensaje encriptado al servidor
    socket_cliente.send(mensaje_encriptado)

    print("Mensaje encriptado enviado al servidor")

    # Cerrar el socket del cliente
    socket_cliente.close()

# Llamar a la función principal
main()
