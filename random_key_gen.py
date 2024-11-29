import random
import sys

hex_char = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

def generate_random_hex_str(length):
    hex_str = ''
    for _ in range(length):
        hex_str += hex_char[random.randint(0, 15)]
    return hex_str

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) > 0:
        if isinstance(args[0], str) and args[0] == 'key':
            print(generate_random_hex_str(64))
        elif isinstance(args[0], str) and args[0] == 'iv':
            print(generate_random_hex_str(32))
        else:
            print('Invalid argument. Use "key" or "iv" as an argument.')
    else:
        print(f'key: {generate_random_hex_str(64)}')
        print(f'iv : {generate_random_hex_str(32)}')
