"""\
GLO-2000 Travail pratique 3 2024
"""

import argparse
import socket
import sys
from typing import NoReturn
from wsgiref.simple_server import server_version

import glosocket
import glocrypto
from glocrypto import generate_random_integer


def _parse_args(argv: list[str]) -> tuple[str, int]:
    """
    Utilise `argparse` pour récupérer les arguments contenus dans argv.

    Retourne un tuple contenant:
    - l'adresse IP du serveur (vide en mode serveur).
    - le port.
    """
    # À revoir ~~~

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target-port", type=int, action="store", required=True, help="Port du serveur.")    # port equipe : 51640

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-l", "--listen", action="store", help="Démarre l'application en mode serveur.")
    group.add_argument("-d", "--destination", type=str, action="store", help="Adresse IP à laquelle le client doit se connecter.")

    args = parser.parse_args(argv)

    # Car listen et destination ne peuvent pas être utilisées en même temps, cependant au moins une doit être utilisée.
    if args.listen :
        return "", args.target_port    # En mode serveur
    return args.destination, args.target_port      # En mode client


def _generate_modulus_base(destination: socket.socket) -> tuple[int, int]:
    """
    Cette fonction génère le modulo et la base à l'aide du module `glocrypto`.

    Elle les transmet respectivement dans deux
    messages distincts à la destination.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """
    modulo = glocrypto.find_prime()  # nombre premier aléatoire qui sert du modulo
    base = glocrypto.generate_random_integer(modulo)    # Base

    glosocket.snd_mesg(destination, str(modulo))    # Transmet modulo
    glosocket.snd_mesg(destination, str(base))      # Transmet base

    return modulo, base


def _receive_modulus_base(source: socket.socket) -> tuple[int, int]:
    """
    Cette fonction reçoit le modulo et la base depuis le socket source.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """
    modulo = int(glosocket.recv_mesg(source))
    base = int(glocrypto.generate_random_integer(modulo))

    return modulo, base


def _compute_two_keys(modulus: int, base: int) -> tuple[int, int]:
    """
    Génère une clé privée et en déduit une clé publique.

    Retourne un tuple contenant respectivement:
    - la clé privée,
    - la clé publique.
    """

    cle_privee = glocrypto.generate_random_integer(modulus)
    cle_publique = glocrypto.modular_exponentiation(base, cle_privee, modulus)

    return cle_privee, cle_publique


def _exchange_public_keys(own_pubkey: int, peer: socket.socket) -> int:
    """
    Envoie sa propre clé publique, récupère la
    clé publique de l'autre et la retourne.
    """

    glosocket.snd_mesg(peer, str(own_pubkey))
    peer_pubkey = int(glocrypto.generate_random_integer(own_pubkey))

    return peer_pubkey


def _compute_shared_key(private_key: int,
                        public_key: int,
                        modulus: int) -> int:
    """Calcule et retourne la clé partagée."""
    # k = (Q^p mod a)     De Alice vers Bob
    # k = (P^q mod a)     Bob reçoit la valeur en calculant

    cle_partagee = glocrypto.modular_exponentiation(public_key, private_key, modulus)

    return cle_partagee


def _server(port: int) -> NoReturn:
    """
    Boucle principale du serveur.

    Prépare son socket, puis gère les clients à l'infini.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', port)) #ip a changer IMPORTANT --> 51640
    s.listen(1) # une personne pour les connexions entrantes acceptées

    while True:
        conn, addr = s.accept()
        try:
            modulus, base = _generate_modulus_base(conn)
            private_key, public_key = _compute_two_keys(modulus, base)
            client_public_key = _exchange_public_keys(public_key, conn)
            _compute_shared_key(private_key, client_public_key, modulus)    # clée partagée
        except glosocket.GLOSocketError:
            print(f"Erreur sur le socket : {glosocket.GLOSocketError}")
        finally:
            conn.close()

def _client(destination: str, port: int) -> None:
    """
    Point d'entrée du client.

    Crée et connecte son socket, puis procède aux échanges.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        with s:
            s.connect((destination, port))

            modulus, base = _receive_modulus_base(s)
            private_key, public_key = _compute_two_keys(modulus, base)
            server_public_key = _exchange_public_keys(public_key, s)
            _compute_shared_key(private_key, server_public_key, modulus)

    except glosocket.GLOSocketError:
        print(f"Erreur sur le socket : {glosocket.GLOSocketError}")
        sys.exit(1)

    finally :
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()   # Socket



# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT

def _main() -> int:
    destination, port = _parse_args(sys.argv[1:])
    if destination:
        _client(destination, port)
    else:
        _server(port)
    return 0


if __name__ == '__main__':
    sys.exit(_main())
