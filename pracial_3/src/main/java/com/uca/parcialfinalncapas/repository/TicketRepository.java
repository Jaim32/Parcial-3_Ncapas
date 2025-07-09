package com.uca.parcialfinalncapas.repository;

import com.uca.parcialfinalncapas.entities.Ticket;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Esta interfaz define el repositorio para la entidad Ticket.
 */
@Repository
public interface TicketRepository extends JpaRepository<Ticket, Long> {
    Optional<Ticket> findById(Long id);

    // ✅ CORRECTO: lista de tickets por usuario
    List<Ticket> findByUsuarioId(Long usuarioId);
}
