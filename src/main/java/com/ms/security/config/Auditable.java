package com.ms.security.config;

import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.ZonedDateTime;

@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@Data
public abstract class Auditable<U> {

    @CreatedBy
    protected U createdBy;

    @CreationTimestamp
    protected ZonedDateTime createdDate;

    @LastModifiedBy
    protected U lastModifiedBy;

    @UpdateTimestamp
    protected ZonedDateTime lastModifiedDate;

    public U getCreatedBy() {
        return createdBy;
    }

}
