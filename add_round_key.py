# website name: https://cryptohack.org/challenges/aes/
# problem name: Round Keys

state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]


round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]

#function that converts matrix values in byte values
def matrix2bytes(matrix):
    return bytes(sum(matrix, []))

#applying XOR operation between state and round_key for getting the flag values
def add_round_key(s, k):
    return matrix2bytes([[s[i][j] ^ k[i][j] for j in range(4)] for i in range(4)])

#printing the flag
print(add_round_key(state, round_key).decode())
