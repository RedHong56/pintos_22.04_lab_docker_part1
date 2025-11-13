#include <stdint.h>

#define F (1<<14)
static inline int int_to_fp(int i);
static inline int fp_to_int(int i);
static inline int fp_to_int_round(int i);

static inline int fp_add_fp(int fp1, int fp2);
static inline int fp_sub_fp(int fp1, int fp2);
static inline int fp_mul_fp(int fp1, int fp2);
static inline int fp_div_fp(int fp1, int fp2);

static inline int fp_add_int(int fp, int i);
static inline int fp_sub_int(int fp, int i);
static inline int fp_mul_int(int fp, int i);
static inline int fp_div_int(int fp, int i);
/////////////////////////////////////////////////
static inline int int_to_fp(int i){
    return i*F;
}
static inline int fp_to_int(int i){
    return i/F;
}
static inline int fp_to_int_round(int i){
    return (i>=0)?(i+F/2)/F:(i-F/2)/F;
}
//////////////////FP, FP 연산 ////////////////////////////
static inline int fp_add_fp(int fp1, int fp2){
    return fp1+fp2;
}
static inline int fp_sub_fp(int fp1, int fp2){
    return fp1-fp2;
}
static inline int fp_mul_fp(int fp1, int fp2){
    return ((int64_t)fp1) * fp2 / F;
}
static inline int fp_div_fp(int fp1, int fp2){
    return ((int64_t)fp1) * F / fp2;
}
/////////////////////FP, INT 계산////////////////////////////
static inline int fp_add_int(int fp, int i){
    return fp + (i * F);
}
static inline int fp_sub_int(int fp, int i){
    return fp - (i * F);
}
static inline int fp_mul_int(int fp, int i){
    return fp*i;
}
static inline int fp_div_int(int fp, int i){
    return fp/i;
}