class Importer:
  """Imports rows."""

  def run(self, rows):
    for row in rows:
      try:
        if row:
          while row.more():
            for cell in row.cells():
~>              try:
                cell.parse()
              except ValueError:
                cell.skip()
      except KeyError:
        pass
