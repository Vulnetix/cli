from optparse import OptionParser

parser = OptionParser()
~>parser.add_option("-f", "--force", action="store_true", dest="force")
parser.add_option("-n", "--dry-run", action="store_true", help="print only")
