#define MAX_DEGREE 16

static double coeff[MAX_DEGREE + 1];

double eval_poly(double x, int degree)
{
    double acc = 0.0;
    for (int i = 0; i <= degree; i++)
        acc = acc * x + coeff[i];
    return acc;
}
