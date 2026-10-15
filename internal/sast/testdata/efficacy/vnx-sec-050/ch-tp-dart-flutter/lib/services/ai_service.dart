import 'package:google_generative_ai/google_generative_ai.dart';

~>const _apiKey = 'AIza@@sample:[0-9A-Za-z_-]{35}@@';

final model = GenerativeModel(model: 'gemini-pro', apiKey: _apiKey);
