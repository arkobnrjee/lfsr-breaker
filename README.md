# LSFR Breaker

The linear shift feedback register (LSFR) is a method of generating a stream of pseudo-random bits. Given a $n$ bit seed $a_1a_2 \dots a_n$ and a tap position $1 \leq t \leq n,$ the LSFR outputs the bit $a_n$ and "shifts" the seed to $ba_1a_2 \dots a_{n-1},$ where $b = a_1 \bigoplus a_t.$ Iterating this procedure produces a sequence of pseudorandom bits as output.

A very naïve encryption method for images involves simply generating a sequence of LSFR pseudorandom bits as long as the number of bits as the image description (for RGB images, this would be $3 \cdot 8 \cdot W \cdot H$ for a $W \times H$ image) and simply taking the exclusive OR of the pseudorandom bits with the image description. The resulting representation can be decrypted using the seed of the LSFR that generated the encrypting pseudorandom bits.

The algorithm in this repository provides a way to break this form of encryption in polynomial time. The algorithm relies on a heuristic that images tend to contain clusters of pixels with relatively constant values (for the purposes of this algorithm, "constant" is defined as pixels whose color values are either all above 128 or all below 128). It samples clusters of pixels and uses them to solve for the value of the LSFR key using a Gaussian Elimination scheme.
