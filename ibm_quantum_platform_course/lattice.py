# Lattice-based cryptography

import numpy as np

def gram_schmidt(B):
    n = B.shape[0]
    B_star = np.zeros_like(B, dtype=float)
    mu = np.zeros((n, n), dtype=float)

    for i in range(n):
        v = B[i].astype(float)
        for j in range(i):
            mu[i, j] = np.dot(B[i], B_star[j]) / np.dot(B_star[j], B_star[j])
            v = v - mu[i, j] * B_star[j]
        B_star[i] = v

    return B_star, mu


def svp_enumeration(B, R):
    n = B.shape[0]
    B_star, mu = gram_schmidt(B)
    best_norm2 = R * R
    best_z = None
    nodes = 0

    z = np.zeros(n, dtype=int)

    def enum(i, partial_norm2):
        nonlocal best_norm2, best_z, nodes
        nodes += 1

        if partial_norm2 >= best_norm2:
            return

        if i < 0:
            if partial_norm2 > 0:
                best_norm2 = partial_norm2
                best_z = z.copy()
            return

        # center for z_i
        c = 0.0
        for j in range(i+1, n):
            c -= mu[j, i] * z[j]

        bound = int(np.sqrt((best_norm2 - partial_norm2) / np.dot(B_star[i], B_star[i])))

        for zi in range(int(np.floor(c - bound)), int(np.ceil(c + bound)) + 1):
            z[i] = zi
            new_norm2 = partial_norm2 + (zi - c)**2 * np.dot(B_star[i], B_star[i])
            enum(i - 1, new_norm2)

    enum(n - 1, 0.0)
    return best_z, np.sqrt(best_norm2), nodes


np.random.seed(0)
B = np.random.randint(-20, 20, size=(20, 20))

print(B)
z, length, nodes = svp_enumeration(B, R=1000)

print("z =", z)
print("shortest length =", length)
print("nodes visited =", nodes)
