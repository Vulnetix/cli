from optparse import OptionParser

p = OptionParser(usage="%prog [options]")
~>p.add_option("-f", "--force", action="store_true", dest="force")
p.add_option("-q", "--quiet", action="store_true", help="be quiet")
(opts, rest) = p.parse_args()
