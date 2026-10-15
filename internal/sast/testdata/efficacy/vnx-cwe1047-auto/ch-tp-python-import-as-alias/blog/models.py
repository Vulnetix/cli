~>import blog.views as views


class Post:
    def __init__(self, title):
        self.title = title

    def url(self):
        return views.permalink(self)
