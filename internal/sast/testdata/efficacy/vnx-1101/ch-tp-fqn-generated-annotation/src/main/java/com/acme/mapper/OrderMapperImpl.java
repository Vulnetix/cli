package com.acme.mapper;

import com.acme.domain.Order;
import com.acme.dto.OrderDto;

~>@javax.annotation.Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2024-03-11T10:15:42+0100"
)
public class OrderMapperImpl implements OrderMapper {

~>    @javax.annotation.PostConstruct
    void init() {
    }

    @Override
    public OrderDto toDto(Order order) {
        if (order == null) {
            return null;
        }
        OrderDto dto = new OrderDto();
        dto.setId(order.getId());
        return dto;
    }
}
