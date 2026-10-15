#include <memory>

enum class LeafKind { Small, Big };

class Leaf {
public:
    virtual ~Leaf() = default;
    LeafKind kind() const { return k_; }
protected:
    LeafKind k_ = LeafKind::Small;
};

class SmallLeaf : public Leaf {
public:
    int size() const { return 4; }
};

class BigLeaf : public Leaf {
public:
    int size() const { return 4096; }
};

class Reader {
    std::unique_ptr<Leaf> m_leaf;
    LeafKind m_leaf_kind = LeafKind::Small;

public:
    int size() const
    {
        if (m_leaf_kind == LeafKind::Small)
            return static_cast<const SmallLeaf &>(*m_leaf).size();
        else
            return static_cast<const BigLeaf &>(*m_leaf).size();
    }
};
