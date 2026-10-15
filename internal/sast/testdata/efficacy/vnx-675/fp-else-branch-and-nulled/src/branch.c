void finish(FILE *fp, int ok)
{
    if (ok)
        fclose(fp);
    else
        fclose(fp);
}

void finish2(FILE *fp, int ok)
{
    if (ok) {
        fclose(fp);
    } else {
        fclose(fp);
    }
}

void reset(FILE **fp)
{
    fclose(*fp);
    *fp = NULL;
    if (*fp)
        fclose(*fp);
}
