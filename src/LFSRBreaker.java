/*
 * This algorithm is probabilistic and runs in expected polynomial time complexity, allowing it
 * to crack binary passwords significantly longer than a regular brute force algorithm.
 * 
 * Let N be the provided size of the binary password, M be the size of the image, and c be a custom
 * parameter denoting the number of retries for the sake of accuracy. The program then runs in
 * O(N(cN^3 + M)) time on average.
 * 
 * The algorithm is probabilistic, relying on the fact that in most original images, contiguous sets
 * of pixels do not change drastically in color. Informally, let p be the probability that given a
 * randomly selected set of N contiguous pixels and a randomly selected color channel (red, green, blue),
 * all pixels in the set have the same first bit for the value of the given color channel. For example,
 * if the selected color channel is red, the N pixels would have to either have all R values >= 128,
 * or all R values < 128. The number of retries needed on average is approximately 1/p. If p is approximately
 * 0, then the algorithm fails. For most practical applications, an empirical estimate of 10 retries
 * should suffice.
 */

 // Note to self: learn to write comments in code.

import java.awt.Color;
import java.util.Stack;

public class LFSRBreaker {
    /* Main client function. Given the password length and the encrypted image, it returns the decrypted image.
     * Returns null if the algorithm could not find any candidate passwords.
     * 
     * @param passwordLength The length of the password.
     * @param encryptedImage The encrypted image.
     * @return Picture The decrypted image.
     */
    public static Picture decryptImage(int passwordLength, Picture encryptedImage) {
        return decryptImage(passwordLength, encryptedImage, false);
    }

    /* Overloaded client function with log printing option. Given the password length and the encrypted image,
     * it returns the decrypted image.
     * Returns null if the algorithm could not find any candidate passwords.
     * 
     * @param passwordLength The length of the password.
     * @param encryptedImage The encrypted image.
     * @param printLog If set to true, the program outputs a password search log to standard output.
     * @return Picture The decrypted image.
     */
    public static Picture decryptImage(int passwordLength, Picture encryptedImage, boolean printLog) {
        return decryptImage(passwordLength, encryptedImage, 10, printLog);
    }

    /* Overloaded client function with all custom parameters. Given the password length, the encrypted image,
     * and the number of retries the program should execute for each candidate tap position, it returns the decrypted image.
     * Returns null if the algorithm could not find any candidate passwords.
     * 
     * @param passwordLength The length of the password.
     * @param encryptedImage The encrypted image.
     * @param numRetries The number of retries per candidate tap position.
     * @param printLog If set to true, the program outputs a password search log to standard output.
     * @return Picture The decrypted image.
     */

    public static Picture decryptImage(int passwordLength, Picture decryptedImage, int numRetries, boolean printLog) {
        int[][][] imageArr = pictureToArray(decryptedImage);
        int numRows = imageArr.length, numCols = imageArr[0].length;
        int[][][] bestPicture = null;
        LFSRKey bestLFSR = null;
        int bestCost = numRows * numCols * 3; // Our best cost will definitely be lower than this.
        if (printLog) {
            System.out.println("Provided password length: " + passwordLength);
        }
        for (int tapPos = 0; tapPos < passwordLength; ++tapPos) {
            if (printLog) {
                System.out.println("Candidate tap position: " + tapPos);
            }
            // Figure out the impact positions.
            // impactPositions.get(r, c, colorChannel) returns a boolean array whose ith element is true
            // if flipping the ith bit in the password impacts the primary bit of the given color channel
            // of the pixel (r, c).
            ImpactPositionCalculator impactPositions = new ImpactPositionCalculator(numRows, numCols, tapPos, passwordLength);
            if (printLog) {
                System.out.println("Impact position calculation done.\n");
            }
            // Actual decryption runs start now.
            for (int trialNum = 1; trialNum <= numRetries; ++trialNum) {
                if (printLog) {
                    System.out.println(String.format("Trial %d of %d", trialNum, numRetries));
                }
                int startRow = (int) (Math.random() * numRows), startCol = (int) (Math.random() * numCols);
                int colorChannel = (int) (Math.random() * 3);
                if (printLog) {
                    String colorChannelAsStr;
                    if (colorChannel == 0) {
                        colorChannelAsStr = "R";
                    } else if (colorChannel == 1) {
                        colorChannelAsStr = "G";
                    } else {
                        colorChannelAsStr = "B";
                    }
                    System.out.println(String.format("Iteration starting at (%d, %d), color channel %s", startRow, startCol, colorChannelAsStr));
                }
                SquareIterator squareGenerator = new SquareIterator(numRows, numCols, startRow, startCol);
                GaussianEliminator zeroSolver = new GaussianEliminator(passwordLength);
                GaussianEliminator oneSolver = new GaussianEliminator(passwordLength);
                int zeroSolutionFound = 0, oneSolutionFound = 0;
                int currSquare = squareGenerator.getNextSquare();
                while (currSquare != -1 && (zeroSolutionFound == 0 || oneSolutionFound == 0)) {
                    int r = currSquare / numCols, c = currSquare % numCols;
                    // The ith value of the impact vector is true if that bit has impact.
                    // The dot product of this vector with the password gives a delta vector.
                    boolean[] impactVector = impactPositions.get(r, c, colorChannel);
                    // Find the current primary bit of this square for this color channel.
                    boolean currPrimary = (imageArr[r][c][colorChannel] >> 7) != 0;
                    // If it's already been concluded, no need to keep adding rows.
                    if (zeroSolutionFound == 0) {
                        zeroSolver.addRow(impactVector, currPrimary);
                    }
                    if (oneSolutionFound == 0) {
                        oneSolver.addRow(impactVector, !currPrimary);
                    }
                    zeroSolutionFound = zeroSolver.getSolvable();
                    oneSolutionFound = oneSolver.getSolvable();
                    // Get new square.
                    currSquare = squareGenerator.getNextSquare();
                }
                if (zeroSolutionFound == 1) {
                    LFSRKey zeroSolution = new LFSRKey(zeroSolver.getSolution(), tapPos);
                    int[][][] outputImage = useLFSR(imageArr, zeroSolution);
                    int cost = evaluateDecryptionCost(outputImage);
                    if (cost < bestCost) {
                        bestCost = cost;
                        bestPicture = outputImage;
                        bestLFSR = zeroSolution;
                    }
                    if (printLog) {
                        System.out.println("Zero-primary-bit solution has been found.");
                        System.out.println(zeroSolution);
                        System.out.println("Cost: " + cost);
                    }
                } else if (printLog) {
                    System.out.println("No zero-primary-bit solution has been found.");
                }
                if (oneSolutionFound == 1) {
                    LFSRKey oneSolution = new LFSRKey(oneSolver.getSolution(), tapPos);
                    int[][][] outputImage = useLFSR(imageArr, oneSolution);
                    int cost = evaluateDecryptionCost(outputImage);
                    if (cost < bestCost) {
                        bestCost = cost;
                        bestPicture = outputImage;
                        bestLFSR = oneSolution;
                    }
                    if (printLog) {
                        System.out.println("One-primary-bit solution has been found.");
                        System.out.println(oneSolution);
                        System.out.println("Cost: " + cost);
                    }
                } else if (printLog) {
                    System.out.println("No one-primary-bit solution has been found.");
                }
            }
            if (printLog) {
                System.out.println("\n\n"); // We separate out tap positions with multiple newlines for readability.
                if (bestLFSR == null) {
                    System.out.println("<No valid LFSR keys found yet>");
                } else {
                    System.out.println("Current best cost: " + bestCost);
                    System.out.println(bestLFSR);
                }
                System.out.println("\n\n");
            }
        }
        if (bestPicture == null) {
            return null;
        }
        return arrayToPicture(bestPicture);
    }

    // Provides a decrypted image a score/cost. Lower cost is better.
    private static int evaluateDecryptionCost(int[][][] imageArr) {
        int numRows = imageArr.length, numCols = imageArr[0].length;
        boolean[][] used;
        int numComps = 0;
        for (int colorChannel = 0; colorChannel < 3; ++colorChannel) {
            used = new boolean[numRows][numCols];
            for (int r = 0; r < numRows; ++r) {
                for (int c = 0; c < numCols; ++c) {
                    if (!used[r][c]) {
                        dfs(r, c, imageArr, used, colorChannel);
                        ++numComps;
                    }
                }
            }
        }
        return numComps;
    }

    // Implements the LFSR on an array image representation.
    private static int[][][] useLFSR(int[][][] imageArr, LFSRKey key) {
        int numRows = imageArr.length, numCols = imageArr[0].length;
        int[][][] newImage = new int[numRows][numCols][3];
        boolean[] encryptionBits = nextNBits(24 * numRows * numCols, key);
        int currBitPos = 0;
        for (int r = 0; r < numRows; ++r) {
            for (int c = 0; c < numCols; ++c) {
                for (int colorChannel = 0; colorChannel < 3; ++colorChannel) {
                    int toXor = 0;
                    for (int i = 0; i < 8; ++i) {
                        toXor <<= 1;
                        if (encryptionBits[currBitPos]) {
                            toXor |= 1;
                        }
                        ++currBitPos;
                    }
                    newImage[r][c][colorChannel] = imageArr[r][c][colorChannel] ^ toXor;
                }
            }
        }
        return newImage;
    }

    // DFS search
    private static void dfs(int rootR, int rootC, int[][][] imageArr, boolean[][] used, int colorChannel) {
        // Making this recursive took up too much memory.
        // We'll use a stack instead.
        // We encapsulate (r,c) as the integer r * numCols + c.
        int numRows = imageArr.length, numCols = imageArr[0].length;
        Stack<Integer> dfsStack = new Stack<>();
        dfsStack.push(rootR * numCols + rootC);
        while (!dfsStack.empty()) {
            int top = dfsStack.pop();
            int r = top / numCols;
            int c = top % numCols;            
            used[r][c] = true;
            // The primary bit of two color values can be asserted to
            // be equal if the xor of the numbers has primary bit 0.
            if (r > 0 && !used[r - 1][c] 
            && (imageArr[r][c][colorChannel] ^ imageArr[r - 1][c][colorChannel]) >> 7 == 0) {
                dfsStack.push((r - 1) * numCols + c);
            }
            if (c > 0 && !used[r][c - 1]
            && (imageArr[r][c][colorChannel] ^ imageArr[r][c - 1][colorChannel]) >> 7 == 0) {
                dfsStack.push(r * numCols + c - 1);
            }
            if (r < numRows - 1 && !used[r + 1][c]
            && (imageArr[r][c][colorChannel] ^ imageArr[r + 1][c][colorChannel]) >> 7 == 0) {
                dfsStack.push((r + 1) * numCols + c);
            }
            if (c < numCols - 1 && !used[r][c + 1]
            && (imageArr[r][c][colorChannel] ^ imageArr[r][c + 1][colorChannel]) >> 7 == 0) {
                dfsStack.push(r * numCols + c + 1);
            }
        }
    }

    // Finds the next n bits outputted by an LFSR.
    private static boolean[] nextNBits(int n, LFSRKey lfsr) {
        boolean[] values = new boolean[n];
        int passwordLength = lfsr.binaryPassword.length;
        int leftIndex = 0, rightIndex = passwordLength - lfsr.tapPos - 1;
        for (int i = 0; i < n; ++i) {
            if (leftIndex >= passwordLength) {
                // We have exceeded bounds of the initial password.
                values[i] ^= values[leftIndex - passwordLength];
            } else {
                values[i] ^= lfsr.binaryPassword[leftIndex];
            }
            if (rightIndex >= passwordLength) {
                values[i] ^= values[rightIndex - passwordLength];
            } else {
                values[i] ^= lfsr.binaryPassword[rightIndex];
            }
            ++leftIndex;
            ++rightIndex;
        }
        return values;
    }

    // Convert picture to 3D array. arr[r][c] corresponds to the rgb values of pixel (r, c).
    // This converts rows in the image to columns in the array, so row-major iteration is used.
    private static int[][][] pictureToArray(Picture pic) {
        int width = pic.width(), height = pic.height();
        int[][][] arrayRep = new int[width][height][3];
        for (int x = 0; x < width; ++x) {
            for (int y = 0; y < height; ++y) {
                Color currPixel = pic.get(x, y);
                // Represent the color of the current pixel as a list and add it on.
                arrayRep[x][y] = new int[]{currPixel.getRed(), currPixel.getGreen(), currPixel.getBlue()};
            }
        }
        return arrayRep;       
    }

    // Convert 3D array to picture. arr[r][c] corresponds to the rgb values of pixel (r, c).
    // This converts rows in the image to columns in the array, so row-major iteration is used.
    private static Picture arrayToPicture(int[][][] arrayRep) {
        // Since each column in the picture is a row in the array, the width is the length of a column here.
        int width = arrayRep.length, height = arrayRep[0].length;
        Picture outputImage = new Picture(width, height);
        for (int x = 0; x < width; ++x) {
            for (int y = 0; y < height; ++y) {
                int[] currPixelArr = arrayRep[x][y];
                Color currPixel = new Color(currPixelArr[0], currPixelArr[1], currPixelArr[2]);
                outputImage.set(x, y, currPixel);
            }
        }
        return outputImage;
    }

    private static class ImpactPositionCalculator {
        private int tapDistance, numCols, passwordLength;
        private boolean[] leftBits, tapBits;

        // We can use the similar behavior of the LFSR across different password bit positions to
        // massively speed up impact position finding. Instantiation takes O(numRows * numCols) time,
        // albeit with a rather large constant factor of 24. Get queries happen in O(1).
        public ImpactPositionCalculator(int numRows, int numCols, int tapPos, int passwordLength) {
            // Distance between leftmost bit and tap position bit.
            this.passwordLength = passwordLength;
            this.numCols = numCols; // This is to find the right bit index.
            tapDistance = passwordLength - tapPos - 1;
            LFSRKey trialKey = new LFSRKey(new boolean[passwordLength], tapPos);
            trialKey.binaryPassword[0] = true;
            leftBits = nextNBits(24 * numRows * numCols, trialKey);
            trialKey.binaryPassword[0] = false;
            trialKey.binaryPassword[tapDistance] = true;
            tapBits = nextNBits(24 * numRows * numCols, trialKey);
        }

        // Returns boolean array. The ith entry is true if flipping the ith password bit
        // impacts the primary bit of the given color channel of pixel (row, col).
        public boolean[] get(int row, int col, int colorChannel) {
            int indexDesired = 24 * row * numCols + 24 * col + 8 * colorChannel;
            boolean[] impactVector = new boolean[passwordLength];
            int actualIndex = indexDesired;
            for (int i = 0; i < tapDistance; ++i) {
                impactVector[i] = actualIndex < 0 ? false : leftBits[actualIndex];
                --actualIndex;
            }
            actualIndex = indexDesired;
            for (int i = tapDistance; i < passwordLength; ++i) {
                impactVector[i] = actualIndex < 0 ? false : tapBits[actualIndex];
                --actualIndex;
            }
            return impactVector;
        }
    }

    private static class GaussianEliminator {
        private int length, numSpotsNeeded, solvability;
        private boolean[][] squareMatrix;
        private boolean[] results;

        public GaussianEliminator(int length) {
            this.length = numSpotsNeeded = length;
            solvability = 0;
            squareMatrix = new boolean[length][length];
            results = new boolean[length];
        }

        // Returns 1 if solution is found, 0 if solution is not yet found, and -1 if no solution exists.
        public int getSolvable() {
            return solvability;
        }

        // Add a row to the linear system.
        public void addRow(boolean[] xVector, boolean yValue) {
            if (solvability == -1) {
                return;
            }
            // We can't change the values in the xVector array without messing things up on the outside.
            // We need to create a clone.
            boolean[] xVectorClone = xVector.clone();
            boolean rowInserted = false;
            for (int i = 0; i < length && !rowInserted; ++i) {
                if (xVectorClone[i]) {
                    // Current bit is set to true.
                    if (!squareMatrix[i][i]) {
                        // We don't have an entry for this position yet. We can add this.
                        for (int j = 0; j < length; ++j) {
                            squareMatrix[i][j] = xVectorClone[j];
                        }
                        results[i] = yValue;
                        --numSpotsNeeded;
                        rowInserted = true;
                    } else {
                        // Add the ith row to xVectorClone.
                        for (int j = 0; j < length; ++j) {
                            xVectorClone[j] ^= squareMatrix[i][j];
                        }
                        yValue ^= results[i];
                    }
                }
            }
            if (!rowInserted) {
                if (yValue) {
                    solvability = -1;
                }
            } else if (numSpotsNeeded == 0) {
                solvability = 1;
            }
        }

        // Returns a solution. Note that the client needs to check solvability == 1 before using this.
        // Otherwise the answer may not be correct.
        public boolean[] getSolution() {
            boolean[] solution = new boolean[length];
            for (int i = length - 1; i >= 0; --i) {
                // Use the previously calculated values to solve row i of the square matrix.
                solution[i] = results[i];
                for (int j = i + 1; j < length; ++j) {
                    solution[i] ^= (solution[j] & squareMatrix[i][j]);
                }
            }
            return solution;
        }
    }

    private static class SquareIterator {
        private int numCols;
        private int leftBound, rightBound, upBound, downBound;
        private int finalLeftBound, finalRightBound, finalUpBound, finalDownBound;
        private int currRow, currCol, finalRow, finalCol;
        private int deltaRow, deltaCol;
        private Direction currDirection;
        private boolean done;

        // This might actually be the cleanest way to do this.
        // Dealing with directions as integers is an annoying amount of casework.

        private static final Direction UP = new Direction() {
            public boolean movable(SquareIterator iterator) {
                return iterator.upBound != iterator.finalUpBound;
            }

            public void setIterator(SquareIterator iterator) {
                --iterator.upBound;
                iterator.currRow = iterator.finalRow = iterator.upBound;
                iterator.currCol = iterator.leftBound;
                iterator.finalCol = iterator.rightBound;
                iterator.deltaRow = 0;
                iterator.deltaCol = 1;
            }
        };

        private static final Direction DOWN = new Direction() {
            public boolean movable(SquareIterator iterator) {
                return iterator.downBound != iterator.finalDownBound;
            }

            public void setIterator(SquareIterator iterator) {
                ++iterator.downBound;
                iterator.currRow = iterator.finalRow = iterator.downBound;
                iterator.currCol = iterator.rightBound;
                iterator.finalCol = iterator.leftBound;
                iterator.deltaRow = 0;
                iterator.deltaCol = -1;
            }
        };

        private static final Direction LEFT = new Direction() {
            public boolean movable(SquareIterator iterator) {
                return iterator.leftBound != iterator.finalLeftBound;
            }

            public void setIterator(SquareIterator iterator) {
                --iterator.leftBound;
                iterator.currRow = iterator.downBound;
                iterator.finalRow = iterator.upBound;
                iterator.currCol = iterator.finalCol = iterator.leftBound;
                iterator.deltaRow = -1;
                iterator.deltaCol = 0;
            }
        };
        
        private static final Direction RIGHT = new Direction() {
            public boolean movable(SquareIterator iterator) {
                return iterator.rightBound != iterator.finalRightBound;
            }

            public void setIterator(SquareIterator iterator) {
                ++iterator.rightBound;
                iterator.currRow = iterator.upBound;
                iterator.finalRow = iterator.downBound;
                iterator.currCol = iterator.finalCol = iterator.rightBound;
                iterator.deltaRow = 1;
                iterator.deltaCol = 0;
            }
        };

        // Here, (r, c) is the start position.
        // It is considered as already used.
        public SquareIterator(int numRows, int numCols, int r, int c) {
            this.numCols = numCols; // We need this to convert squares to integers.
            leftBound = rightBound = c;
            upBound = downBound = r;
            finalLeftBound = 0;
            finalRightBound = numCols - 1;
            finalUpBound = 0;
            finalDownBound = numRows - 1;
            currRow = finalRow = r;
            currCol = finalCol = c;
            // Orient the directions.
            UP.next = RIGHT;
            RIGHT.next = DOWN;
            DOWN.next = LEFT;
            LEFT.next = UP;
            currDirection = DOWN;
            deltaRow = 1;
            deltaCol = 0;
            done = false;
        }

        // Returns the next square.
        // A square (r, c) is encapsulated as r * numCols + c.
        // Returns -1 if no more new squares exist.
        public int getNextSquare() {
            if (done) {
                return -1;
            }
            int returnSquare = currRow * numCols + currCol;
            if (currRow != finalRow || currCol != finalCol) {
                currRow += deltaRow;
                currCol += deltaCol;
            } else {
                Direction nextDirection = currDirection.next;
                while (!nextDirection.movable(this)) {
                    if (nextDirection == currDirection) {
                        done = true;
                        return returnSquare;
                    }
                    nextDirection = nextDirection.next;
                }
                currDirection.next = nextDirection;
                currDirection = nextDirection;
                currDirection.setIterator(this);
            }
            return returnSquare;
        }

        private static abstract class Direction {
            private Direction next;

            // Is it possible to move in this direction now?
            public abstract boolean movable(SquareIterator iterator);
            // Set the iterator correctly.
            public abstract void setIterator(SquareIterator iterator);
        }
    }

    // Wrapper class for LFSR parameters.
    // Contains the password and tap position.
    private static class LFSRKey {
        private boolean[] binaryPassword;
        private int tapPos;

        public LFSRKey(boolean[] binaryPassword, int tapPos) {
            this.binaryPassword = binaryPassword;
            this.tapPos = tapPos;
        }

        public String toString() {
            String stringForm = "Binary Password: ";
            for (boolean b : binaryPassword) {
                if (b) {
                    stringForm += "1";
                } else {
                    stringForm += "0";
                }
            }
            stringForm += "\nTap position: " + tapPos;
            return stringForm;
        }
    }
}
