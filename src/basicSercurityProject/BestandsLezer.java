package basicSercurityProject;

import java.io.*;

public class BestandsLezer {
	private String bestandsNaam;
	private BufferedReader f;
	
	public BestandsLezer(String bestandsNaam) throws IOException {
		this.bestandsNaam = bestandsNaam;
		f = new BufferedReader(new FileReader(this.bestandsNaam));
	}
	public String leesRegel() throws IOException {
		String regel;
		try {
			regel = f.readLine();
		} catch (EOFException e) {
			regel =null;
		}
		return regel;
	}
	
	public int leesInt() throws IOException {
		String regel = leesRegel();
		int getal = Integer.parseInt(regel);
		return getal;
	}
	
	public float leesFloat() throws IOException {
		String regel = leesRegel();
		float getal = Float.parseFloat(regel);
		return getal;
	}
	
	public double leesDouble() throws IOException {
		String regel = leesRegel();
		double getal = Double.parseDouble(regel);
		return getal;
	}
	
}
