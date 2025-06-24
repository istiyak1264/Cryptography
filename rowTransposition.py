#!/bin/python3
def create_matrix(plaintext, cols):
    rows = (len(plaintext) + cols - 1) // cols
    matrix = []
    i = 0
    for _ in range(rows):
        row = []
        for _ in range(cols):
            if i < len(plaintext):
                row.append(plaintext[i])
                i += 1
            else:
                row.append('x')
        matrix.append(row)
    return matrix


def encrypt_row_transposition(matrix, key):
    key_order = [int(x) for x in str(key)]
    column_order = [index for index, _ in sorted(enumerate(key_order), key=lambda x: x[1])]
    return ''.join(matrix[row][col] for col in column_order for row in range(len(matrix)))


def decrypt_row_transposition(ciphertext, key, rows):
    cols = len(str(key))
    key_order = [int(x) for x in str(key)]
    column_order = [index for index, _ in sorted(enumerate(key_order), key=lambda x: x[1])]
    col_len = rows
    columns = {}
    i = 0
    for col in column_order:
        columns[col] = list(ciphertext[i:i+col_len])
        i += col_len
    return ''.join(columns[col][row] for row in range(rows) for col in range(cols))


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ").upper().replace(" ", "")
    key = int(input("Enter numeric key: "))
    cols = len(str(key))
    matrix = create_matrix(plaintext, cols)
    ciphertext = encrypt_row_transposition(matrix, key)
    print("Encrypted text:", ciphertext)
    rows = len(matrix)
    decrypted = decrypt_row_transposition(ciphertext, key, rows)
    print("Decrypted text:", decrypted)
