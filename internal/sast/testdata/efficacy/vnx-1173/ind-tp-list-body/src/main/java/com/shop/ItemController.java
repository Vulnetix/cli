package com.shop;

import javax.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@Controller
public class ItemController {

    @PostMapping("/item")
    @ResponseBody
    public Item add(@RequestBody @Valid ItemDto dto) {
        return svc.add(dto);
    }

    @PostMapping("/items")
    @ResponseBody
~>    public List<Item> addAll(@RequestBody List<ItemDto> dtos) {
        return svc.addAll(dtos);
    }
}
