static int next_state(int s, char c)
{
	switch (c) {
	case 'a':
		return 1;
~>	default:
		s = 0;
	case 'z':
		s = 2;
		break;
	}
	return s;
}
