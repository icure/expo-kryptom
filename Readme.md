## Dependencies

### ios

Dependency to XCFramework, created through `updateIosFramework` npm script.
Note that this requires the `icure-multiplatform-sdk` submodule to be initialised.

### android

For development we can use builds of kryptom published to maven local. FOr some reason we have to add maven local in
the `example/android/build.gradle` file... It seems like it is not necessary to add it to the `android/build.gradle` 
file for development, however, if in future we use a non-maven-central repository for the publishing of our artifacts
we may need to add the repository configuration also there.

## Editing

Intellij idea has some issues with the android part, android studio works better. To open the project in android studio
and xcode you can use the following commands:

```bash
npm run open:android
npm run open:ios
```

## Running the example app

To run the example app you can use the following commands:

```bash
npm run build
```
```bash
cd example
npx expo run:ios
npx expo run:android
```