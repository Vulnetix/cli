package com.acme.repo;

import java.util.List;
import org.springframework.data.jpa.repository.Query;

public interface ArticleRepository {
    @Query(value = """
            SELECT a.* FROM article a
~>            WHERE a.title ILIKE '%' || :term || '%'
            ORDER BY a.published DESC
            """, nativeQuery = true)
    List<Article> search(String term);

~>    @Query(value = "SELECT * FROM tag t WHERE t.name ILIKE CONCAT('%', :q)", nativeQuery = true)
    List<Tag> tags(String q);
}
