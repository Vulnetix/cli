SquareClient client = new SquareClient.Builder()
    .environment(Environment.PRODUCTION)
~>    .bearerAuthCredentials(new BearerAuthModel.Builder("@@sample:EAAA[a-z]{3}[0-9]{3}[A-Z]{3}[A-Za-z0-9_-]{51}@@").build())
    .build();
