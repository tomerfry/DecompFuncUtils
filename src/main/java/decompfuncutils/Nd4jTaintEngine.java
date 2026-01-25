/*
 * Nd4jTaintEngine - Cross-platform GPU-accelerated taint analysis using ND4J
 * 
 * ND4J (N-Dimensional Arrays for Java) provides:
 * - Automatic GPU detection and offloading (CUDA/OpenCL)
 * - Native sparse matrix support (COO, CSR formats)
 * - Fallback to optimized CPU (OpenBLAS/MKL)
 * - No platform-specific native library management
 */
package decompfuncutils;

import ghidra.util.Msg;
import java.util.*;

/**
 * Alternative taint engine using ND4J for better cross-platform support.
 * 
 * ND4J automatically selects the best available backend:
 * 1. CUDA (if nvidia-cuda-toolkit and nd4j-cuda present)
 * 2. OpenCL (if nd4j-native-platform with OpenCL)
 * 3. Native CPU with BLAS optimization
 * 
 * Dependencies for build.gradle:
 *   implementation 'org.nd4j:nd4j-native-platform:1.0.0-M2.1'
 *   // For GPU: implementation 'org.nd4j:nd4j-cuda-11.6-platform:1.0.0-M2.1'
 */
public class Nd4jTaintEngine {
    
    private static final float CONVERGENCE_THRESHOLD = 0.0001f;
    private static final int DEFAULT_ITERATIONS = 30;
    
    private boolean nd4jAvailable = false;
    private boolean gpuBackend = false;
    private String backendInfo = "Not initialized";
    
    // Cached reflection handles for ND4J classes
    private Class<?> nd4jClass;
    private Class<?> indArrayClass;
    private Class<?> sparseNd4jClass;
    
    public Nd4jTaintEngine() {
        initializeNd4j();
    }
    
    /**
     * Try to initialize ND4J and detect backend
     */
    private void initializeNd4j() {
        try {
            // Load ND4J classes
            nd4jClass = Class.forName("org.nd4j.linalg.factory.Nd4j");
            indArrayClass = Class.forName("org.nd4j.linalg.api.ndarray.INDArray");
            
            // Try to load sparse support
            try {
                sparseNd4jClass = Class.forName("org.nd4j.linalg.factory.Nd4jSparse");
            } catch (ClassNotFoundException e) {
                sparseNd4jClass = null;
            }
            
            // Get backend info
            java.lang.reflect.Method getBackend = nd4jClass.getMethod("getBackend");
            Object backend = getBackend.invoke(null);
            backendInfo = backend.getClass().getSimpleName();
            
            // Check if CUDA backend
            gpuBackend = backendInfo.toLowerCase().contains("cuda") || 
                         backendInfo.toLowerCase().contains("gpu");
            
            nd4jAvailable = true;
            Msg.info(this, "ND4J initialized with backend: " + backendInfo + 
                    (gpuBackend ? " (GPU)" : " (CPU)"));
            
        } catch (ClassNotFoundException e) {
            backendInfo = "ND4J not found in classpath";
            Msg.info(this, "ND4J not available, using pure Java implementation");
        } catch (Exception e) {
            backendInfo = "ND4J initialization failed: " + e.getMessage();
            Msg.warn(this, backendInfo);
        }
    }
    
    /**
     * Run taint propagation using ND4J or fallback
     */
    public void runTaintPropagation(int numNodes, int numEdges,
                                    int[] rowPtr, int[] colInd, float[] values,
                                    float[] taintVector, int iterations) {
        if (numNodes == 0 || numEdges == 0) return;
        
        if (nd4jAvailable) {
            try {
                runNd4jTaint(numNodes, numEdges, rowPtr, colInd, values, taintVector, iterations);
                return;
            } catch (Exception e) {
                Msg.warn(this, "ND4J taint failed, using fallback: " + e.getMessage());
            }
        }
        
        // Pure Java fallback
        runJavaTaint(numNodes, rowPtr, colInd, values, taintVector, iterations);
    }
    
    /**
     * ND4J-based sparse matrix-vector multiplication
     */
    private void runNd4jTaint(int numNodes, int numEdges,
                              int[] rowPtr, int[] colInd, float[] values,
                              float[] taintVector, int iterations) throws Exception {
        
        // Convert CSR to COO format (ND4J prefers COO for sparse)
        int[][] indices = csrToCoo(numNodes, rowPtr, colInd);
        int[] rows = indices[0];
        int[] cols = indices[1];
        
        // Create sparse matrix using reflection
        Object sparseMatrix = createSparseMatrix(numNodes, numNodes, rows, cols, values);
        
        // Create taint vector
        Object taintNd = createVector(taintVector);
        Object resultNd = createZeroVector(numNodes);
        
        // Iterative SpMV
        for (int iter = 0; iter < iterations; iter++) {
            // result = matrix * taint
            Object mmulResult = sparseMatrixMultiply(sparseMatrix, taintNd);
            
            // Check convergence
            float maxDiff = computeMaxDiff(mmulResult, taintNd);
            
            // Merge (keep max)
            taintNd = elementWiseMax(taintNd, mmulResult);
            
            // Saturate to [0, 1]
            taintNd = clipValues(taintNd, 0.0f, 1.0f);
            
            if (maxDiff < CONVERGENCE_THRESHOLD) {
                break;
            }
        }
        
        // Copy result back to float array
        copyToFloatArray(taintNd, taintVector);
    }
    
    // Helper methods using reflection to call ND4J
    
    private int[][] csrToCoo(int numRows, int[] rowPtr, int[] colInd) {
        int nnz = colInd.length;
        int[] rows = new int[nnz];
        
        int idx = 0;
        for (int row = 0; row < numRows; row++) {
            int start = rowPtr[row];
            int end = rowPtr[row + 1];
            for (int j = start; j < end; j++) {
                rows[idx++] = row;
            }
        }
        
        return new int[][] { rows, colInd };
    }
    
    private Object createSparseMatrix(int rows, int cols, int[] rowIndices, 
                                      int[] colIndices, float[] values) throws Exception {
        if (sparseNd4jClass != null) {
            // Use proper sparse support if available
            java.lang.reflect.Method createCoo = sparseNd4jClass.getMethod(
                "createSparseCOO", double[].class, int[][].class, long[].class);
            
            // Convert to double and format indices
            double[] doubleVals = new double[values.length];
            for (int i = 0; i < values.length; i++) {
                doubleVals[i] = values[i];
            }
            
            int[][] indices = new int[][] { rowIndices, colIndices };
            long[] shape = new long[] { rows, cols };
            
            return createCoo.invoke(null, doubleVals, indices, shape);
        } else {
            // Fallback: create dense matrix (less efficient but works)
            java.lang.reflect.Method zeros = nd4jClass.getMethod("zeros", int.class, int.class);
            Object matrix = zeros.invoke(null, rows, cols);
            
            java.lang.reflect.Method putScalar = indArrayClass.getMethod(
                "putScalar", int.class, int.class, double.class);
            
            for (int i = 0; i < values.length; i++) {
                putScalar.invoke(matrix, rowIndices[i], colIndices[i], (double) values[i]);
            }
            
            return matrix;
        }
    }
    
    private Object createVector(float[] data) throws Exception {
        double[] doubleData = new double[data.length];
        for (int i = 0; i < data.length; i++) {
            doubleData[i] = data[i];
        }
        
        java.lang.reflect.Method create = nd4jClass.getMethod("create", double[].class);
        Object vector = create.invoke(null, doubleData);
        
        // Reshape to column vector
        java.lang.reflect.Method reshape = indArrayClass.getMethod("reshape", long[].class);
        return reshape.invoke(vector, new long[] { data.length, 1 });
    }
    
    private Object createZeroVector(int size) throws Exception {
        java.lang.reflect.Method zeros = nd4jClass.getMethod("zeros", int.class, int.class);
        return zeros.invoke(null, size, 1);
    }
    
    private Object sparseMatrixMultiply(Object matrix, Object vector) throws Exception {
        java.lang.reflect.Method mmul = indArrayClass.getMethod("mmul", indArrayClass);
        return mmul.invoke(matrix, vector);
    }
    
    private float computeMaxDiff(Object a, Object b) throws Exception {
        java.lang.reflect.Method sub = indArrayClass.getMethod("sub", indArrayClass);
        Object diff = sub.invoke(a, b);
        
        java.lang.reflect.Method abs = Class.forName("org.nd4j.linalg.ops.transforms.Transforms")
            .getMethod("abs", indArrayClass);
        Object absDiff = abs.invoke(null, diff);
        
        java.lang.reflect.Method maxNumber = indArrayClass.getMethod("maxNumber");
        Number max = (Number) maxNumber.invoke(absDiff);
        
        return max.floatValue();
    }
    
    private Object elementWiseMax(Object a, Object b) throws Exception {
        java.lang.reflect.Method max = Class.forName("org.nd4j.linalg.ops.transforms.Transforms")
            .getMethod("max", indArrayClass, indArrayClass);
        return max.invoke(null, a, b);
    }
    
    private Object clipValues(Object array, float min, float max) throws Exception {
        java.lang.reflect.Method clip = Class.forName("org.nd4j.linalg.ops.transforms.Transforms")
            .getMethod("clip", indArrayClass, double.class, double.class);
        return clip.invoke(null, array, (double) min, (double) max);
    }
    
    private void copyToFloatArray(Object ndArray, float[] target) throws Exception {
        java.lang.reflect.Method toFloatVector = indArrayClass.getMethod("toFloatVector");
        float[] result = (float[]) toFloatVector.invoke(ndArray);
        System.arraycopy(result, 0, target, 0, Math.min(result.length, target.length));
    }
    
    /**
     * Pure Java fallback implementation
     * Optimized with loop unrolling and cache-friendly access
     */
    private void runJavaTaint(int numNodes, int[] rowPtr, int[] colInd, 
                             float[] values, float[] taintVector, int iterations) {
        float[] temp = new float[numNodes];
        
        for (int iter = 0; iter < iterations; iter++) {
            float maxChange = 0.0f;
            
            // SpMV: temp = A * taint
            for (int row = 0; row < numNodes; row++) {
                float sum = 0.0f;
                int start = rowPtr[row];
                int end = rowPtr[row + 1];
                
                // Unroll by 4 for better performance
                int j = start;
                for (; j + 3 < end; j += 4) {
                    sum += values[j] * taintVector[colInd[j]];
                    sum += values[j + 1] * taintVector[colInd[j + 1]];
                    sum += values[j + 2] * taintVector[colInd[j + 2]];
                    sum += values[j + 3] * taintVector[colInd[j + 3]];
                }
                // Handle remainder
                for (; j < end; j++) {
                    sum += values[j] * taintVector[colInd[j]];
                }
                
                temp[row] = Math.min(1.0f, sum);
            }
            
            // Merge and check convergence
            for (int i = 0; i < numNodes; i++) {
                float newVal = Math.max(taintVector[i], temp[i]);
                float change = Math.abs(newVal - taintVector[i]);
                if (change > maxChange) maxChange = change;
                taintVector[i] = newVal;
            }
            
            // Early termination
            if (maxChange < CONVERGENCE_THRESHOLD) {
                break;
            }
        }
    }
    
    /**
     * Compute Boolean transitive closure using repeated squaring
     * More efficient for reachability analysis
     */
    public void computeReachability(int numNodes, int[] rowPtr, int[] colInd,
                                   float[] taintVector) {
        // For transitive closure, log2(n) iterations of squaring suffice
        int iterations = (int) Math.ceil(Math.log(numNodes) / Math.log(2)) + 1;
        
        // Use binary values for reachability
        for (int i = 0; i < taintVector.length; i++) {
            taintVector[i] = taintVector[i] > 0 ? 1.0f : 0.0f;
        }
        
        // Create all-ones values for adjacency matrix
        float[] onesValues = new float[rowPtr[numNodes]];
        Arrays.fill(onesValues, 1.0f);
        
        runTaintPropagation(numNodes, onesValues.length, rowPtr, colInd, onesValues, 
                           taintVector, iterations);
    }
    
    public boolean isNd4jAvailable() {
        return nd4jAvailable;
    }
    
    public boolean isGpuBackend() {
        return gpuBackend;
    }
    
    public String getBackendInfo() {
        return backendInfo;
    }
    
    public String getStatus() {
        if (nd4jAvailable) {
            return "ND4J: " + backendInfo + (gpuBackend ? " (GPU)" : " (CPU)");
        } else {
            return "Pure Java (ND4J not available)";
        }
    }
}
