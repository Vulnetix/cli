package app;

public class UploadController {
    public String upload(MultipartFile file) {
        String originalName = file.getOriginalFilename();
~>        String ext = originalName.substring(originalName.indexOf("."));
~>        if (!originalName.contains(".pdf")) {
            throw new IllegalArgumentException("pdf only");
        }
        return ext;
    }
}
