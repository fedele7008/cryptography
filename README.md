# cryptography

컴파일 하는법:
* gcc 사용자일 경우: `gcc chacha20.c -o chacha20`
* clang 사용자일 경우: `clang chacha20.c -o chacha20`

실행 방법:
1. 다음 환경 변수를 설정해 주세요
    ```
    chacha20_key=$(python3 random_key_gen.py key)
    chacha20_iv=$(python3 random_key_gen.py iv)
    ```
1. ChaCha20 으로 암호화 하는법:
    ```
    ./chacha20 <암호화 할 평문 파일이름> <생성될 암호문 파일이름> ${chacha20_key} ${chacha20_iv}
    ```
    예시:
    ```
    ./chacha20 plaintext.txt my_encrypted.bin ${chacha20_key} ${chacha20_iv}
    ```

1. ChaCha20 으로 복호화 하는법:
    ```
    ./chacha20 <복호화 할 암호문 파일이름> <생성될 평문 파일이름> ${chacha20_key} ${chacha20_iv}
    ```
    예시:
    ```
    ./chacha20 my_encrypted.bin my_decrypted.txt ${chacha20_key} ${chacha20_iv}
    ```
