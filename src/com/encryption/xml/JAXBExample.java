package com.encryption.xml;

import java.io.File;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

public class JAXBExample {
	private static final String workingKeyDirectoryForJks = System.getProperty("user.dir");

	public static void writeXml(User user) throws JAXBException {

		File file = new File(workingKeyDirectoryForJks + File.separator + "user.xml");
		JAXBContext jaxbContext = JAXBContext.newInstance(User.class);
		Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
		jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		jaxbMarshaller.marshal(user, file);
		jaxbMarshaller.marshal(user, System.out);
	}

	public static String readFromXml() throws JAXBException {
		File file = new File(workingKeyDirectoryForJks + File.separator + "user.xml");
		JAXBContext jaxbContext = JAXBContext.newInstance(User.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		User user = (User) unmarshaller.unmarshal(file);
		return user.getPassword();

	}
}
