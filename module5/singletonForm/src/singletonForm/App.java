package singletonForm;

public class App {

	public static void main(String[] args) {
		// une seule instance de l'objet
		// par exemple, pour un objet Configuration, une resource partag�e...etc
		
		Configuration c1 = Configuration.getTheInstance();
		System.out.println(c1);
		c1.setVersion("2.0");
		System.out.println(c1);
		
		// je recupere en fait la m�me instance que dans c1
		Configuration c2 = Configuration.getTheInstance();
		System.out.println(c2);
		
		

	}

}
