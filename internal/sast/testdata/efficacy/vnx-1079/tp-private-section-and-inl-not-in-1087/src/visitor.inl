namespace ast {

~>class Visitor {
public:
    virtual void visit_node(int id);
    virtual void visit_leaf(int id);
};

}  // namespace ast
