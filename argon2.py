##  UNIVERSIDAD DEL VALLE DE GUATEMALA
##  CIFRADO DE INFORMACIÓN
##  LABORATORIO 4
##  GRUPO 7
##
##  Ejemplo del funcionamiento de Argon2, sus tres variantes
##
##  Referencia de la librería utilizada (argon2-cffi):
##  https://pypi.org/project/argon2-cffi/

from argon2 import PasswordHasher

##  PasswordHasher recibe varios atributos:
##      * type(str) --> Indica qué tipo de Argon2 se usará
##      * parallelism(int) --> Define el factor de paralelización. Esto puede afectar el resultado del hash.
##      * memory_cost(int) --> Define la cantidad de momeria en kibibytes.
##      * salt(str) --> Número opcional de bytes a usar.
##      * hash_length(int) --> indica el largo del hash
##      * time_cost(int) --> Define la cantidad de cálculos realizado, por ende, el tiempo de ejecucuón.


#   No le ponemos ningún parámetro para que utilice los parámetros default
#   PasswordHasher(type = argon2.Type.ID, hash_length = 16, memory_cost = 102400, parallelism = 8, time_cost = 2)
ph = PasswordHasher()

text = input("Ingrese el texto que desea cifrar: ")

hash = ph.hash(text)

print("Texto cifrado: " + hash)

is_identical = ph.verify(hash, text)

if is_identical == True :
  print("El texto cifrado \n " + hash + " \nes igual a \n " + text)

else :
  print("Los textos no coinciden")
