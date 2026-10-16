void Tree::rebuild()
{
    delete root_;
    root_ = new Node();
    populate(root_);
    delete root_;
    root_ = nullptr;
}
