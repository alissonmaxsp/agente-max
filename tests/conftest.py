import sys
import os

# Adiciona o diretório raiz do projeto ao sys.path para permitir importações absolutas de 'src'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
