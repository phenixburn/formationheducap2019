package com.edugroupe.springjdbcForm.beans;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import com.edugroupe.springjdbcForm.metier.Produit;

import lombok.Getter;
import lombok.Setter;

public class ProduitDAO implements IProduitDAO {
	
	public static final String FIND_ALL_SQL = "SELECT `id`,`nom`,`prix`,`poids` FROM `produits`";
	public static final String FIND_ONE_SQL = "SELECT `id`,`nom`,`prix`,`poids` FROM `produits` WHERE `id`=?";
	public static final String UPDATE_ONE_SQL = "UPDATE `produits` SET `nom`=?,`prix`=?,`poids`=? WHERE `id`=?";
	public static final String INSERT_ONE_SQL = "INSERT INTO `produits` (`nom`,`prix`,`poids`) VALUES (?,?,?)";

	@Getter @Setter
	private JdbcTemplate jdbcTemplate;
	
	// cet classe/objet interne sert à faire la correspondance entre une ligne
	// renvoyé par la requette (via resultSet) et un objet Produit
	// la méthode MapRow sera automatiquement utilisée par
	// le jdbcTemplate auquel on aura fournit notre ProduitMapper
	// le jdbcTemplate se charge du reste, execution de la requette, parcours du resultset, etc.
	private static class ProduitMapper implements RowMapper<Produit> {
		@Override
		public Produit mapRow(ResultSet rs, int rowNum) throws SQLException {
			return new Produit(rs.getInt("id"),
								rs.getString("nom"),
								rs.getDouble("prix"),
								rs.getDouble("poids"));
		}
	}
	
	@Override
	public List<Produit> findAll() {
		return jdbcTemplate.query(FIND_ALL_SQL, new ProduitMapper());
	}
	
	@Override
	public Produit findById(int id) {
		return jdbcTemplate.queryForObject(FIND_ONE_SQL, new Object[] {id}, new ProduitMapper());
	}
	
	@Override
	public int save(Produit p) {
		if (p.getId() == 0) 
			return jdbcTemplate.update(INSERT_ONE_SQL, p.getNom(), p.getPrix(),p.getPoids());
		else
			return jdbcTemplate.update(UPDATE_ONE_SQL, p.getNom(), p.getPrix(),p.getPoids(), p.getId());
		
	}
	
}
