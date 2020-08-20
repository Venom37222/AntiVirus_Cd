public class DetectionsDisplay
{
    private String fileName;
    private String fileLoaction;
    private String fileDescription;

    public DetectionsDisplay(String fileName, String fileDescription, String fileLoaction) {
        this.fileName = fileName;
        this.fileLoaction = fileLoaction;
        this.fileDescription = fileDescription;
    }

    // get the program name
    public String getFileName() {
        return fileName;
    }

    // get the location of the threat
    public String getFileLoaction() {
        return fileLoaction;
    }

    // actually find where the threat is located
    public String getFileDescription() {
        return fileDescription;
    }
}
